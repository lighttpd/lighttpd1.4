#ifndef _LIGHTTPD_SETTINGS_H_
#define _LIGHTTPD_SETTINGS_H_

#define BV(x) (1 << x)

#define INET_NTOP_CACHE_MAX 4
#define FILE_CACHE_MAX      16

/**
 * max size of a buffer which will just be reset
 * to ->used = 0 instead of really freeing the buffer
 *
 * 64kB (no real reason, just a guess)
 */
#define BUFFER_MAX_REUSE_SIZE  (4 * 1024)

/**
 * max size of the HTTP request header
 *
 * 32k should be enough for everything (just a guess)
 *
 */
#define MAX_HTTP_REQUEST_HEADER  (32 * 1024)

typedef enum { HANDLER_UNSET,
		HANDLER_GO_ON,
		HANDLER_FINISHED,
		HANDLER_COMEBACK,
		HANDLER_WAIT_FOR_EVENT,
		HANDLER_ERROR,
		HANDLER_WAIT_FOR_FD
} handler_t;


/* we use it in a enum */
#ifdef TRUE
#undef TRUE
#endif

#ifdef FALSE
#undef FALSE
#endif

#endif
