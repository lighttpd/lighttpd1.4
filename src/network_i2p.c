#include "first.h"

#include "network_backends.h"

#if defined(HAVE_I2P)

#include "fdevent.h"
#include "libsam3.h"
#include "log.h"
#include "network.h"

#include <errno.h>
#include <sys/ioctl.h>

static inline void strcpyseserr (Sam3Session *ses, const char *errstr) {
	memset(ses->error, 0, sizeof(ses->error));
	if (errstr != NULL) strncpy(ses->error, errstr, sizeof(ses->error)-1);
}

static inline void strcpyconnerr (Sam3Connection *conn, const char *errstr) {
	memset(conn->error, 0, sizeof(conn->error));
	if (errstr != NULL) strncpy(conn->error, errstr, sizeof(conn->error)-1);
}

Sam3Connection *get_listener(Sam3Session *ses) {
	SAMFieldList *rep = NULL;
	Sam3Connection *conn;

	if (ses->type != SAM3_SESSION_STREAM) {
		strcpyseserr(ses, "INVALID_SESSION_TYPE");
		errno = EBADF;
		return NULL;
	}
	if (ses->fd < 0) {
		strcpyseserr(ses, "INVALID_SESSION");
		errno = EBADF;
		return NULL;
	}
	if ((conn = calloc(1, sizeof(Sam3Connection))) == NULL) {
		strcpyseserr(ses, "NO_MEMORY");
		errno = ENOMEM;
		return NULL;
	}
	if ((conn->fd = sam3HandshakeIP(ses->ip, ses->port)) < 0) {
		strcpyseserr(ses, "IO_ERROR_SK");
		errno = EADDRNOTAVAIL;
		goto error;
	}
	if (sam3tcpPrintf(conn->fd, "STREAM ACCEPT ID=%s\n", ses->channel) < 0) {
		strcpyseserr(ses, "IO_ERROR_PF");
		errno = EADDRNOTAVAIL;
		goto error;
	}
	if ((rep = sam3ReadReply(conn->fd)) == NULL) {
		strcpyseserr(ses, "IO_ERROR_RP");
		errno = EADDRNOTAVAIL;
		goto error;
	}
	if (!sam3IsGoodReply(rep, "STREAM", "STATUS", "RESULT", "OK")) {
		const char *v = sam3FindField(rep, "RESULT");
		strcpyseserr(ses, (v != NULL && v[0] ? v : "I2P_ERROR_RES"));
		errno = EADDRNOTAVAIL;
		goto error;
	}
	sam3FreeFieldList(rep);
	conn->ses = ses;
	conn->next = ses->connlist;
	ses->connlist = conn;
	strcpyseserr(ses, NULL);
	return conn;

error:
	if (rep != NULL) sam3FreeFieldList(rep);
	if (conn->fd >= 0) sam3tcpDisconnect(conn->fd);
	free(conn);
	return NULL;
}

int check_listener(Sam3Connection *conn) {
	SAMFieldList *rep = NULL;
	char repstr[1024];
	int count;

	ioctl(conn->fd, FIONREAD, &count);
	if (count == 0) {
		errno = EWOULDBLOCK;
		return -1;
	}

	if (sam3tcpReceiveStr(conn->fd, repstr, sizeof(repstr)) < 0) {
		strcpyconnerr(conn, "IO_ERROR_RP1");
		errno = ECONNABORTED;
		goto error;
	}
	if ((rep = sam3ParseReply(repstr)) != NULL) {
		const char *v = sam3FindField(rep, "RESULT");
		strcpyconnerr(conn, (v != NULL && v[0] ? v : "I2P_ERROR_RES1"));
		errno = EPROTO;
		goto error;
	}
	if (strlen(repstr) != SAM3_PUBKEY_SIZE) {
		strcpyconnerr(conn, "INVALID_KEY");
		errno = EPROTO;
		goto error;
	}
	sam3FreeFieldList(rep);
	strcpy(conn->destkey, repstr);
	return 0;

error:
	if (rep != NULL) sam3FreeFieldList(rep);
	sam3CloseConnection(conn);
	return -1;
}

int bind_i2p(server *srv, specific_config *s, server_socket *srv_socket,
		const char *i2p_keyname, unsigned int port) {
	buffer *ob;
	buffer *kpb;
	buffer *kb;
	FILE *fl;
	char i2p_keybuffer[SAM3_PRIVKEY_SIZE+1];

	/* Prepare SAM options */
	ob = buffer_init();
	if (!buffer_is_empty(s->i2p_sam_nickname)) {
		buffer_copy_string_len(ob, CONST_STR_LEN("inbound.nickname=\""));
		buffer_append_string_buffer(ob, s->i2p_sam_nickname);
		buffer_append_string_len(ob, CONST_STR_LEN("\""));
	} else {
		buffer_copy_string_len(ob, CONST_STR_LEN("inbound.nickname=lighttpd-"));
		buffer_append_string(ob, i2p_keyname);
	}

	/* Prepare keyfile prefix */
	kpb = buffer_init();
	if (!buffer_is_empty(srv->srvconf.i2p_sam_keydir)) {
		buffer_copy_buffer(kpb, srv->srvconf.i2p_sam_keydir);
		buffer_append_string_len(kpb, CONST_STR_LEN("/"));
	}
	buffer_append_string(kpb, i2p_keyname);

	/* Read in the Destination */
	kb = buffer_init();
	buffer_copy_buffer(kb, kpb);
	buffer_append_string_len(kb, CONST_STR_LEN(".privkey"));
	if (!buffer_is_empty(srv->srvconf.i2p_sam_keydir)) {
		buffer_path_simplify(kb, kb);
	}

	if ((fl = fopen(kb->ptr, "rt")) != NULL) {
		fgets(i2p_keybuffer, SAM3_PRIVKEY_SIZE+1, fl);
		fclose(fl);

		log_error_write(srv, __FILE__, __LINE__, "ss", "Creating SAMv3 session for", i2p_keyname);
		if (sam3CreateSession(&(srv_socket->i2p_ses), srv->srvconf.i2p_sam_host, srv->srvconf.i2p_sam_port, i2p_keybuffer, SAM3_SESSION_STREAM, ob->ptr) < 0) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "SAMv3 SESSION CREATE failed:", strerror(errno));
			return -1;
		}
		log_error_write(srv, __FILE__, __LINE__, "s", "Session built");
	} else {
		/* No file, so open a transient SAMv3 session and save its key */
		log_error_write(srv, __FILE__, __LINE__, "sss", "Creating SAMv3 session for", i2p_keyname, "with new Destination");
		if (sam3CreateSession(&(srv_socket->i2p_ses), srv->srvconf.i2p_sam_host, srv->srvconf.i2p_sam_port, SAM3_DESTINATION_TRANSIENT, SAM3_SESSION_STREAM, ob->ptr) < 0) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "SAMv3 SESSION CREATE failed:", strerror(errno));
			return -1;
		}
		log_error_write(srv, __FILE__, __LINE__, "s", "Session built");

		if ((fl = fopen(kb->ptr, "wt")) != NULL) {
			fwrite(srv_socket->i2p_ses.privkey, strlen(srv_socket->i2p_ses.privkey), 1, fl);
			fclose(fl);
			log_error_write(srv, __FILE__, __LINE__, "ss", "Private key saved to", kb->ptr);
		} else {
			log_error_write(srv, __FILE__, __LINE__, "sss", "WARNING: Could not save private key to", kb->ptr, "; Destination will be lost on shutdown.");
		}
	}
	buffer_free(ob);
	buffer_free(kb);

	/* Export current Destination as B64 */
	kb = buffer_init();
	buffer_copy_buffer(kb, kpb);
	buffer_append_string_len(kb, CONST_STR_LEN(".b64.txt"));
	if (!buffer_is_empty(srv->srvconf.i2p_sam_keydir)) {
		buffer_path_simplify(kb, kb);
	}
	if ((fl = fopen(kb->ptr, "wt")) != NULL) {
		fwrite(srv_socket->i2p_ses.pubkey, strlen(srv_socket->i2p_ses.pubkey), 1, fl);
		fclose(fl);
		log_error_write(srv, __FILE__, __LINE__, "ss", "Destination B64 saved to", kb->ptr);
	} else {
		log_error_write(srv, __FILE__, __LINE__, "ss", "WARNING: Could not save Destination B64 to", kb->ptr);
	}
	buffer_free(kb);

#ifdef USE_OPENSSL
	/* Calculate B32 */
	int raw_dest_len;
	unsigned char *raw_dest = i2p_unbase64(srv_socket->i2p_ses.pubkey, strlen(srv_socket->i2p_ses.pubkey), &raw_dest_len);
	unsigned char *hash = SHA256(raw_dest, raw_dest_len, 0);
	free(raw_dest);
	char b32_hash[56];
	sam3Base32Encode(b32_hash, hash, strlen(hash));
	char *eq_pos = strchrnul(b32_hash, '=');
	eq_pos[0] = '\0';
	buffer *b32;
	b32 = buffer_init();
	buffer_copy_string(b32, b32_hash);
	buffer_append_string_len(b32, CONST_STR_LEN(".b32.i2p"));

	/* Export B32 */
	kb = buffer_init();
	buffer_copy_string_buffer(kb, kpb);
	buffer_append_string_len(kb, CONST_STR_LEN(".b32.txt"));
	if (!buffer_is_empty(srv->srvconf.i2p_sam_keydir)) {
		buffer_path_simplify(kb, kb);
	}
	if ((fl = fopen(kb->ptr, "wt")) != NULL) {
		fwrite(b32->ptr, strlen(b32->ptr), 1, fl);
		fclose(fl);
		log_error_write(srv, __FILE__, __LINE__, "ss", "Destination B32 saved to", kb->ptr);
	} else {
		log_error_write(srv, __FILE__, __LINE__, "ss", "WARNING: Could not save Destination B32 to", kb->ptr);
	}
	buffer_free(kb);
#endif

	buffer_free(kpb);

	return 0;
}

int add_listener(server *srv, server_socket *srv_socket) {
	i2p_listener *l;
	if ((l = calloc(1, sizeof(i2p_listener))) == NULL) {
		strcpyseserr(&(srv_socket->i2p_ses), "NO_MEMORY");
		errno = ENOMEM;
		return -1;
	}
	l->conn = get_listener(&(srv_socket->i2p_ses));
	if (l->conn == NULL) {
		free(l);
		return -1;
	}
	l->fde_ndx = -1;
	l->next = srv_socket->i2p_listeners;
	srv_socket->i2p_listeners = l;
	if (srv != NULL) {
		network_register_i2p_fdevent(srv, srv_socket, l);
	}
	return 0;
}

int listen_i2p(server_socket *srv_socket, int backlog) {
	// libsam3 currently only supports SAM v3.0; multi-accept was added in v3.2
	int v32 = 0;
	for (int i = 0; i < (v32 ? backlog : 1); i++) {
		if (0 != add_listener(NULL, srv_socket)) {
			return -1;
		}
	}
	return 0;
}

int accept_i2p(server *srv, server_socket *srv_socket, struct sockaddr *addr, socklen_t *addrlen) {
	i2p_listener *l = srv_socket->i2p_listeners;
	i2p_listener *prev = NULL;
	while (l != NULL) {
		if (check_listener(l->conn)) {
			if (prev == NULL) {
				srv_socket->i2p_listeners = l->next;
			} else {
				prev->next = l->next;
			}

			int fd = l->conn->fd;
			if (l->fde_ndx != -1) {
				fdevent_event_del(srv->ev, &(l->fde_ndx), fd);
				fdevent_unregister(srv->ev, fd);
			}
			free(l);

			// TODO Should this error-out (dropping the new conn), or log?
			if (0 != add_listener(srv, srv_socket)) {
				return -1;
			}

			return fd;
		} else if (errno != EWOULDBLOCK) {
			return -1;
		}
		prev = l;
		l = l->next;
	}
	return -1;
}
#endif /* HAVE_I2P */
