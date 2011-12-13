
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_LUA_UDT_MODULE_H_INCLUDED_
#define _NGX_LUA_UDT_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_udt.h>
#include <ngx_lua.h>


#define NGX_LUA_UDT_TABLE  "udt_srv"


typedef struct {
    void                 **conf;
} ngx_lua_udt_main_conf_t;


typedef struct {
    ngx_lua_script_t       script;
    void                 **conf;
} ngx_lua_udt_srv_conf_t;


typedef struct {
    ngx_udt_session_t     *s;
    ngx_chain_t           *out;
    ngx_chain_t           *last;
    ngx_int_t              rc;
    ngx_uint_t             not_event;
} ngx_lua_udt_ctx_t;


extern ngx_dll ngx_module_t  ngx_lua_udt_module;


#endif /* _NGX_LUA_UDT_MODULE_H_INCLUDED_ */
