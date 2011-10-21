
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_LUA_UDP_MODULE_H_INCLUDED_
#define _NGX_LUA_UDP_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_udp.h>
#include <ngx_lua.h>


#define NGX_LUA_UDP_TABLE  "udp_srv"


typedef struct {
    void                 **conf;
} ngx_lua_udp_main_conf_t;


typedef struct {
    ngx_lua_script_t       script;
    void                 **conf;
} ngx_lua_udp_srv_conf_t;


typedef struct {
    ngx_udp_session_t     *s;
    ngx_chain_t           *out;
    ngx_chain_t           *last;
} ngx_lua_udp_ctx_t;


#endif /* _NGX_LUA_UDP_MODULE_H_INCLUDED_ */