#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef HAVE_FASTCGI_FASTCGI_H
#include <fastcgi/fcgi_stdio.h>
#else
#include <fcgi_stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main (void) {
	while (FCGI_Accept() >= 0) {
		/* wait for fastcgi authorizer request */
		char* p = getenv("QUERY_STRING");

		/* Status: 200 OK to allow access is implied when not included in response */
		if (p != NULL && 0 == strcmp(p, "var")) {
			printf("Variable-X-LIGHTTPD-FCGI-AUTH: LighttpdTestContent\r\n");
		} else if (p == NULL || 0 != strcmp(p, "ok")) {
			printf("Status: 403 Forbidden\r\n");
		}

		printf("\r\n");
	}

	return 0;
}
