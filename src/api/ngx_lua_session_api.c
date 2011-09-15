
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_module.h>


static int ngx_lua_session_create(lua_State *l);
static int ngx_lua_session_destroy(lua_State *l);
static int ngx_lua_session_set_param(lua_State *l);
static int ngx_lua_session_get_param(lua_State *l);
static int ngx_lua_session_index(lua_State *l);
static int ngx_lua_session_newindex(lua_State *l);


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
    int  n;

    n = sizeof(ngx_lua_session_consts) / sizeof(ngx_lua_const_t) - 1;
    n += sizeof(ngx_lua_session_methods) / sizeof(luaL_Reg) - 1;

    lua_createtable(l, 0, n);

    for (n = 0; ngx_lua_session_consts[n].name != NULL; n++) {
        lua_pushinteger(l, ngx_lua_session_consts[n].value);
        lua_setfield(l, -2, ngx_lua_session_consts[n].name);
    }

    for (n = 0; ngx_lua_session_methods[n].name != NULL; n++) {
        lua_pushcfunction(l, ngx_lua_session_methods[n].func);
        lua_setfield(l, -2, ngx_lua_session_methods[n].name);
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
    ngx_pool_t           *pool;
    ngx_session_ctx_t    *ctx;
    ngx_http_request_t   *r;
    ngx_lua_main_conf_t  *lmcf;

    r = ngx_lua_request(l);

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_session_ctx_t));

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_module);

    if (lmcf->session_mode == NGX_SESSION_MODE_SINGLE) {
        ngx_session_create(&lmcf->session, ctx);
    }

    /* TODO */

    return 0;
}


static int
ngx_lua_session_destroy(lua_State *l)
{
    ngx_pool_t           *pool;
    ngx_session_ctx_t    *ctx;
    ngx_http_request_t   *r;
    ngx_lua_main_conf_t  *lmcf;

    r = ngx_lua_request(l);

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_session_ctx_t));

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_module);

    if (lmcf->session_mode == NGX_SESSION_MODE_SINGLE) {
        ngx_session_destroy(&lmcf->session, ctx);
    }

    /* TODO */

    return 0;
}


static int
ngx_lua_session_set_param(lua_State *l)
{
    ngx_pool_t           *pool;
    ngx_session_ctx_t    *ctx;
    ngx_http_request_t   *r;
    ngx_lua_main_conf_t  *lmcf;

    r = ngx_lua_request(l);

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_session_ctx_t));

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_module);

    if (lmcf->session_mode == NGX_SESSION_MODE_SINGLE) {
        ngx_session_set_param(&lmcf->session, ctx);
    }

    /* TODO */

    return 0;
}


static int
ngx_lua_session_get_param(lua_State *l)
{
    ngx_pool_t           *pool;
    ngx_session_ctx_t    *ctx;
    ngx_http_request_t   *r;
    ngx_lua_main_conf_t  *lmcf;

    r = ngx_lua_request(l);

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_session_ctx_t));

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_module);

    if (lmcf->session_mode == NGX_SESSION_MODE_SINGLE) {
        ngx_session_get_param(&lmcf->session, ctx);
    }

    /* TODO */

    return 0;
}


static int
ngx_lua_session_index(lua_State *l)
{
    ngx_pool_t           *pool;
    ngx_session_ctx_t    *ctx;
    ngx_http_request_t   *r;
    ngx_lua_main_conf_t  *lmcf;

    r = ngx_lua_request(l);

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_session_ctx_t));

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_module);

    if (lmcf->session_mode == NGX_SESSION_MODE_SINGLE) {
        ngx_session_get_var(&lmcf->session, ctx);
    }

    /* TODO */

    return 0;
}


static int
ngx_lua_session_newindex(lua_State *l)
{
    ngx_pool_t           *pool;
    ngx_session_ctx_t    *ctx;
    ngx_http_request_t   *r;
    ngx_lua_main_conf_t  *lmcf;

    r = ngx_lua_request(l);

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_session_ctx_t));

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_module);

    if (lmcf->session_mode == NGX_SESSION_MODE_SINGLE) {
        ngx_session_set_var(&lmcf->session, ctx);

        ngx_session_del_var(&lmcf->session, ctx);
    }

    /* TODO */

    return 0;
}
