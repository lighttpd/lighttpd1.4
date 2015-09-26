/*
 * Public domain.
 * Written by Matthew Dempsky.
 */

#include <string.h>

__attribute__((weak)) void
__explicit_bzero_hook(void *buf, size_t len)
{
}

void
explicit_bzero(void *buf, size_t len)
{
	memset(buf, 0, len);
	__explicit_bzero_hook(buf, len);
}
