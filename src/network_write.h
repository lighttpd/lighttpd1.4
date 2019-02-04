#ifndef INCLUDED_NETWORK_WRITE_H
#define INCLUDED_NETWORK_WRITE_H
#include "first.h"
#include "base_decls.h"

int network_write_init(server *srv);

__attribute_cold__
const char * network_write_show_handlers(void);

#endif
