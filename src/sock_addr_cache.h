#ifndef INCLUDED_SOCK_ADDR_CACHE_H
#define INCLUDED_SOCK_ADDR_CACHE_H
#include "first.h"

#include "buffer.h"
#include "sock_addr.h"

int sock_addr_cache_inet_ntop_copy_buffer(buffer * restrict b, const sock_addr * restrict saddr);

#endif
