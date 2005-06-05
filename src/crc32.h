#ifndef __crc32cr_table_h__
#define __crc32cr_table_h__

#include <sys/types.h>

unsigned long generate_crc32c(char *string, size_t length);

#endif
