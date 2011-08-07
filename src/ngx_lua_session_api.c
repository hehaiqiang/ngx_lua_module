
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_module.h>


#define NGX_LUA_SESSION_CREATE     1
#define NGX_LUA_SESSION_DESTROY    2
#define NGX_LUA_SESSION_SET_PARAM  3
#define NGX_LUA_SESSION_GET_PARAM  4
#define NGX_LUA_SESSION_SET_VAR    5
#define NGX_LUA_SESSION_GET_VAR    6
#define NGX_LUA_SESSION_DEL_VAR    7


typedef struct {
    ngx_http_request_t    *r;
    ngx_uint_t             op;
} ngx_lua_session_ctx_t;


static int ngx_lua_session_create(lua_State *l);
static int ngx_lua_session_destroy(lua_State *l);
static int ngx_lua_session_set_param(lua_State *l);
static int ngx_lua_session_get_param(lua_State *l);
static int ngx_lua_session_index(lua_State *l);
static int ngx_lua_session_newindex(lua_State *l);

static int ngx_lua_session_init(lua_State *l, ngx_uint_t op);


static ngx_lua_const_t  ngx_lua_session_consts[] = {
    { NULL, 0 }
};


static luaL_Reg  ngx_lua_session_methods[] = {
    { "create", ngx_lua_session_create },
    { "destroy", ngx_lua_session_destroy },
    { "set_param", ngx_lua_session_set_param },
    { "get_param", ngx_lua_session_get_param },
    { NULL, NULL }
};


void
ngx_lua_session_api_init(lua_State *l)
{
    int  i, n;

    n = sizeof(ngx_lua_session_consts) / sizeof(ngx_lua_const_t) - 1;
    n += sizeof(ngx_lua_session_methods) / sizeof(luaL_Reg) - 1;

    lua_createtable(l, 0, n);

    for (i = 0; ngx_lua_session_consts[i].name != NULL; i++) {
        lua_pushinteger(l, ngx_lua_session_consts[i].value);
        lua_setfield(l, -2, ngx_lua_session_consts[i].name);
    }

    for (i = 0; ngx_lua_session_methods[i].name != NULL; i++) {
        lua_pushcfunction(l, ngx_lua_session_methods[i].func);
        lua_setfield(l, -2, ngx_lua_session_methods[i].name);
    }

    lua_createtable(l, 0, 2);
    lua_pushcfunction(l, ngx_lua_session_index);
    lua_setfield(l, -2, "__index");
    lua_pushcfunction(l, ngx_lua_session_newindex);
    lua_setfield(l, -2, "__newindex");
    lua_setmetatable(l, -2);

    lua_setfield(l, -2, "session");
}


static int
ngx_lua_session_create(lua_State *l)
{
    return ngx_lua_session_init(l, NGX_LUA_SESSION_CREATE);
}


static int
ngx_lua_session_destroy(lua_State *l)
{
    return ngx_lua_session_init(l, NGX_LUA_SESSION_DESTROY);
}


static int
ngx_lua_session_set_param(lua_State *l)
{
    return ngx_lua_session_init(l, NGX_LUA_SESSION_SET_PARAM);
}


static int
ngx_lua_session_get_param(lua_State *l)
{
    return ngx_lua_session_init(l, NGX_LUA_SESSION_GET_PARAM);
}


static int
ngx_lua_session_index(lua_State *l)
{
    return ngx_lua_session_init(l, NGX_LUA_SESSION_GET_VAR);
}


static int
ngx_lua_session_newindex(lua_State *l)
{
    /* TODO: NGX_LUA_SESSION_DEL_VAR */
    return ngx_lua_session_init(l, NGX_LUA_SESSION_SET_VAR);
}


static int
ngx_lua_session_init(lua_State *l, ngx_uint_t op)
{
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    return luaL_error(l, "test error...");
}
