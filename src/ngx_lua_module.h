
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_LUA_MODULE_H_INCLUDED_
#define _NGX_LUA_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_dbd.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>


typedef struct {
    ngx_str_t       path;
    ngx_str_t       cpath;
    lua_State      *l;
} ngx_lua_main_conf_t;


typedef struct {
    ngx_str_t       path;
    ngx_buf_t      *lsp;
    ngx_buf_t      *buf;

    ngx_chain_t    *out;
    ngx_chain_t    *last;

    lua_State      *l;
    int             ref;
    ngx_dbd_t      *dbd;
    int             cmd;
} ngx_lua_ctx_t;


ngx_int_t ngx_lua_state_new(ngx_conf_t *cf, ngx_lua_main_conf_t *lmcf);
void ngx_lua_state_close(void *data);

ngx_int_t ngx_lua_thread_new(ngx_http_request_t *r, ngx_lua_ctx_t *ctx);
void ngx_lua_thread_close(ngx_http_request_t *r, ngx_lua_ctx_t *ctx);
ngx_int_t ngx_lua_thread_run(ngx_http_request_t *r, ngx_lua_ctx_t *ctx, int n);

ngx_http_request_t *ngx_lua_request(lua_State *l);
ngx_int_t ngx_lua_output(ngx_http_request_t *r, u_char *buf, size_t size);
void ngx_lua_finalize(ngx_http_request_t *r, ngx_int_t rc);

ngx_int_t ngx_lua_parse(ngx_http_request_t *r, ngx_lua_ctx_t *ctx);


extern ngx_module_t  ngx_lua_module;


#include <ngx_lua_api.h>


#endif /* _NGX_LUA_MODULE_H_INCLUDED_ */