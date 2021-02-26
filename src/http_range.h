/*
 * http_range - HTTP Range (RFC 7233)
 *
 * Copyright(c) 2015,2021 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef INCLUDED_RANGE_H
#define INCLUDED_RANGE_H
#include "first.h"

#include "base_decls.h"


int http_range_rfc7233 (request_st *r);


#endif
