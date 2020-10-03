#include "first.h"

#include "base.h"
#include "connections.h"

#include <stdlib.h>

connections *connection_joblist;

__attribute_cold__
static void connection_list_resize(connections *conns) {
    conns->size += 16;
    conns->ptr   = realloc(conns->ptr, sizeof(*conns->ptr) * conns->size);
    force_assert(NULL != conns->ptr);
}

void connection_list_append(connections *conns, connection *con) {
    if (conns->used == conns->size) connection_list_resize(conns);
    conns->ptr[conns->used++] = con;
}
