#ifndef ETAG_H
#define ETAG_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "buffer.h"

int etag_is_equal(buffer *etag, const char *matches);
int etag_create(buffer *etag, struct stat *st);
int etag_mutate(buffer *mut, buffer *etag);
	

#endif
