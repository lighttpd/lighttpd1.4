#include <fcgi_stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main () {
	char* p;
	
	while (FCGI_Accept() >= 0) {   
		if (NULL != (p = getenv("QUERY_STRING"))) {
			if (0 == strcmp(p, "lf")) {
				printf("Status: 200 OK\n\n");
			} else if (0 == strcmp(p, "crlf")) {
				printf("Status: 200 OK\r\n\r\n");
			} else if (0 == strcmp(p, "slow-lf")) {
				printf("Status: 200 OK\n");
				fflush(stdout);
				printf("\n");
			} else if (0 == strcmp(p,"slow-crlf")) {
				printf("Status: 200 OK\r\n");
				fflush(stdout);
				printf("\r\n");
			} else {
				printf("Status: 200 OK\r\n\r\n");
			}
		} else {
			printf("Status: 500 Internal Foo\r\n\r\n");
		}
		 
		printf("test123");  
	}

	return 0;
}
