
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_LUA_HTTP_MODULE_H_INCLUDED_
#define _NGX_LUA_HTTP_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_lua.h>


typedef struct {
    ngx_http_request_t    *r;
    ngx_chain_t           *out;
    ngx_chain_t           *last;
    ngx_str_t              request_body;
} ngx_lua_http_ctx_t;


#endif /* _NGX_LUA_HTTP_MODULE_H_INCLUDED_ */