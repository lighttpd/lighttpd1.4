#include "first.h"

#undef NDEBUG
#include <assert.h>
#include <stdlib.h>

#include "mod_evasive.c"

static void test_mod_evasive_check(void) {
    connection c[4];
    memset(&c, 0, sizeof(c));
    c[0].next = &c[1];
    c[1].prev = &c[0];
    c[1].next = &c[2];
    c[2].prev = &c[1];
    c[2].next = &c[3];
    c[3].prev = &c[2];
    sock_addr_inet_pton(&c[0].dst_addr, "10.0.0.1", AF_INET, 80);
    buffer_copy_string_len(&c[0].dst_addr_buf, CONST_STR_LEN("10.0.0.1"));
    sock_addr_inet_pton(&c[1].dst_addr, "10.0.0.2", AF_INET, 80);
    buffer_copy_string_len(&c[1].dst_addr_buf, CONST_STR_LEN("10.0.0.2"));
    sock_addr_inet_pton(&c[2].dst_addr, "10.0.0.3", AF_INET, 80);
    buffer_copy_string_len(&c[2].dst_addr_buf, CONST_STR_LEN("10.0.0.3"));
    sock_addr_inet_pton(&c[3].dst_addr, "10.0.0.4", AF_INET, 80);
    buffer_copy_string_len(&c[3].dst_addr_buf, CONST_STR_LEN("10.0.0.4"));

    c[0].request.state = CON_STATE_HANDLE_REQUEST;
    c[1].request.state = CON_STATE_HANDLE_REQUEST;
    c[2].request.state = CON_STATE_HANDLE_REQUEST;
    c[3].request.state = CON_STATE_HANDLE_REQUEST;

    request_st *r = &c[0].request;
    r->con = &c[0];
    r->tmp_buf                = buffer_init();
    r->conf.errh              = fdlog_init(NULL, -1, FDLOG_FD);
    r->conf.errh->fd          = -1; /* (disable) */

    plugin_data p;
    memset(&p, 0, sizeof(plugin_data));
    p.conf.silent = 1;

    p.conf.max_conns = 1;
    assert(HANDLER_GO_ON == mod_evasive_check_per_ip_limit(r, &p, c));

    p.conf.max_conns = 2;
    assert(HANDLER_GO_ON == mod_evasive_check_per_ip_limit(r, &p, c));

    sock_addr_inet_pton(&c[1].dst_addr, "10.0.0.1", AF_INET, 80);
    buffer_copy_string_len(&c[1].dst_addr_buf, CONST_STR_LEN("10.0.0.1"));
    assert(HANDLER_GO_ON == mod_evasive_check_per_ip_limit(r, &p, c));

    c[2].request.state = CON_STATE_READ;
    sock_addr_inet_pton(&c[1].dst_addr, "10.0.0.1", AF_INET, 80);
    buffer_copy_string_len(&c[1].dst_addr_buf, CONST_STR_LEN("10.0.0.1"));
    assert(HANDLER_GO_ON == mod_evasive_check_per_ip_limit(r, &p, c));

    c[2].request.state = CON_STATE_HANDLE_REQUEST;
    sock_addr_inet_pton(&c[2].dst_addr, "10.0.0.1", AF_INET, 80);
    buffer_copy_string_len(&c[2].dst_addr_buf, CONST_STR_LEN("10.0.0.1"));
    assert(HANDLER_FINISHED == mod_evasive_check_per_ip_limit(r, &p, c));

    for (uint32_t i = 0; i < sizeof(c)/sizeof(*c); ++i)
        buffer_free_ptr(&c[i].dst_addr_buf);
    fdlog_free(r->conf.errh);
    buffer_free(r->tmp_buf);
}

void test_mod_evasive (void);
void test_mod_evasive (void)
{
    test_mod_evasive_check();
}
