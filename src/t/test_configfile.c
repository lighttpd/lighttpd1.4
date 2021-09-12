#include "first.h"

#undef NDEBUG
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "configfile-glue.c"
#include "fdlog.h"

const struct {
    const char *string;
    const char *rmtstr;
    int rmtfamily;
    int expect;
} rmtmask[] = {
    { "1.0.0.1/1",          "1.0.0.1",         AF_INET, 1 }
   ,{ "254.254.254.254/1",  "254.0.0.1",       AF_INET, 1 }
   ,{ "254.254.254.252/31", "254.254.254.253", AF_INET, 1 }
   ,{ "254.254.254.253/31", "254.254.254.254", AF_INET, 0 }
   ,{ "254.254.254.253/32", "254.254.254.254", AF_INET, 0 }
   ,{ "254.254.254.254/32", "254.254.254.254", AF_INET, 1 }
  #ifdef HAVE_IPV6
   ,{ "2001::/3",           "2001::1",         AF_INET6, 1 }
   ,{ "2f01::/5",           "2701::1",         AF_INET6, 0 }
   ,{ "2f01::/32",          "2f01::1",         AF_INET6, 1 }
   ,{ "2f01::/32",          "2f02::1",         AF_INET6, 0 }
   ,{ "2001::1/127",        "2001::1",         AF_INET6, 1 }
   ,{ "2001::1/127",        "2001::2",         AF_INET6, 0 }
   ,{ "2001::2/128",        "2001::2",         AF_INET6, 1 }
   ,{ "2001::2/128",        "2001::3",         AF_INET6, 0 }
   ,{ "1.0.0.1/1",          "::ffff:1.0.0.1",          AF_INET6, 1 }
   ,{ "254.254.254.254/1",  "::ffff:254.0.0.1",        AF_INET6, 1 }
   ,{ "254.254.254.252/31", "::ffff:254.254.254.253",  AF_INET6, 1 }
   ,{ "254.254.254.253/31", "::ffff:254.254.254.254",  AF_INET6, 0 }
   ,{ "254.254.254.253/32", "::ffff:254.254.254.254",  AF_INET6, 0 }
   ,{ "254.254.254.254/32", "::ffff:254.254.254.254",  AF_INET6, 1 }
   ,{ "::ffff:1.0.0.1/97",          "1.0.0.1",         AF_INET, 1 }
   ,{ "::ffff:254.254.254.254/97",  "254.0.0.1",       AF_INET, 1 }
   ,{ "::ffff:254.254.254.252/127", "254.254.254.253", AF_INET, 1 }
   ,{ "::ffff:254.254.254.253/127", "254.254.254.254", AF_INET, 0 }
   ,{ "::ffff:254.254.254.253/128", "254.254.254.254", AF_INET, 0 }
   ,{ "::ffff:254.254.254.254/128", "254.254.254.254", AF_INET, 1 }
  #endif
};

static void test_configfile_addrbuf_eq_remote_ip_mask (void) {
	request_st r;
	memset(&r, 0, sizeof(request_st));
	r.conf.errh              = fdlog_init(NULL, -1, FDLOG_FD);
	r.conf.errh->fd          = -1; /* (disable) */

	buffer * const b = buffer_init();
	buffer * const tb = buffer_init();
	sock_addr rmt;

	for (int i = 0; i < (int)(sizeof(rmtmask)/sizeof(rmtmask[0])); ++i) {
		if (1 != sock_addr_inet_pton(&rmt, rmtmask[i].rmtstr, rmtmask[i].rmtfamily, 0)) exit(-1); /*(bad test)*/
		buffer_copy_string(b, rmtmask[i].string);
	  #if 0
		if (!config_remoteip_normalize(b, tb)) exit(-1); /*(bad test)*/
	  #else
		/* modified from configfile.c:config_remoteip_normalize()
		 * to avoid pulling in configfile.c and all dependencies */
		char *slash = strchr(b->ptr, '/');
		if (NULL == slash) exit(-1); /*(bad test)*/
		unsigned long nm_bits = strtoul(slash+1, NULL, 10);
		uint32_t len = slash - b->ptr;
		int family = strchr(b->ptr, ':') ? AF_INET6 : AF_INET;
		char *after = buffer_string_prepare_append(b, 1 + 7 + 28);
		++after; /*(increment to pos after string end '\0')*/
		*(unsigned char *)after = (unsigned char)nm_bits;
		sock_addr * const saddr = (sock_addr *)(((uintptr_t)after+1+7) & ~7);
		if (nm_bits) b->ptr[len]='\0'; /*(sock_addr_inet_pton() w/o CIDR mask)*/
		int rc = sock_addr_inet_pton(saddr, b->ptr, family, 0);
		if (nm_bits) b->ptr[len]='/';
		if (1 != rc) exit(-1); /*(bad test)*/
	  #endif
		const sock_addr * const addr = (sock_addr *)
		  (((uintptr_t)b->ptr + b->used + 1 + 7) & ~7);
		int bits = ((unsigned char *)b->ptr)[b->used];
		int m = sock_addr_is_addr_eq_bits(addr, &rmt, bits);
		if (m != rmtmask[i].expect) {
			fprintf(stderr, "failed assertion: %s %s %s\n",
				rmtmask[i].string,
				rmtmask[i].expect ? "==" : "!=",
				rmtmask[i].rmtstr);
			exit(-1);
		}
	}

	buffer_free(tb);
	buffer_free(b);
	fdlog_free(r.conf.errh);
}

int main (void) {
	test_configfile_addrbuf_eq_remote_ip_mask();

	return 0;
}
