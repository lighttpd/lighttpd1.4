/*
 * h1 - HTTP/1.x protocol layer
 *
 * Copyright(c) 2023 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef LI_H1_H
#define LI_H1_H
#include "first.h"
#include "base_decls.h"

int h1_send_1xx (request_st *r, connection *con);

void h1_send_headers (request_st *r);

int h1_recv_headers (request_st *r, connection *con);

handler_t h1_reqbody_read (request_st *r);

int h1_check_timeout (connection *con, unix_time64_t cur_ts);

#endif
