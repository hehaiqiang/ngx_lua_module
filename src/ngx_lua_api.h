
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_LUA_API_H_INCLUDED_
#define _NGX_LUA_API_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_module.h>


typedef struct {
    char    *name;
    int      value;
} ngx_lua_const_t;


void ngx_lua_api_init(lua_State *l);

void ngx_lua_core_api_init(lua_State *l);
void ngx_lua_dbd_api_init(lua_State *l);
void ngx_lua_req_api_init(lua_State *l);
void ngx_lua_resp_api_init(lua_State *l);


#endif /* _NGX_LUA_API_H_INCLUDED_ */
