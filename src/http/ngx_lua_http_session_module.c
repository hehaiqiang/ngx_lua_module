
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_http_module.h>


static int ngx_lua_http_session_create(lua_State *l);
static int ngx_lua_http_session_destroy(lua_State *l);
static int ngx_lua_http_session_set_param(lua_State *l);
static int ngx_lua_http_session_get_param(lua_State *l);
static int ngx_lua_http_session_index(lua_State *l);
static int ngx_lua_http_session_newindex(lua_State *l);

static ngx_int_t ngx_lua_http_session_module_init(ngx_cycle_t *cycle);


static ngx_lua_const_t  ngx_lua_http_session_consts[] = {
    { NULL, 0 }
};


static luaL_Reg  ngx_lua_http_session_methods[] = {
    { "create", ngx_lua_http_session_create },
    { "destroy", ngx_lua_http_session_destroy },
    { "set_param", ngx_lua_http_session_set_param },
    { "get_param", ngx_lua_http_session_get_param },
    { NULL, NULL }
};


ngx_module_t  ngx_lua_http_session_module = {
    NGX_MODULE_V1,
    NULL,                                  /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_lua_http_session_module_init,      /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


#if (NGX_LUA_DLL)
ngx_module_t **
ngx_lua_get_modules(void)
{
    static ngx_module_t  *modules[] = {
        &ngx_lua_http_session_module,
        NULL
    };

    return modules;
}
#endif


static int
ngx_lua_http_session_create(lua_State *l)
{
#if 0
    ngx_pool_t           *pool;
    ngx_session_ctx_t    *ctx;
    ngx_http_request_t   *r;
    ngx_lua_main_conf_t  *lmcf;

    thr = ngx_lua_thread(l);

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_session_ctx_t));

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_http_module);

    if (lmcf->session_mode == NGX_SESSION_MODE_SINGLE) {
        ngx_session_create(&lmcf->session, ctx);
    }

    /* TODO */
#endif

    return 0;
}


static int
ngx_lua_http_session_destroy(lua_State *l)
{
#if 0
    ngx_pool_t           *pool;
    ngx_session_ctx_t    *ctx;
    ngx_http_request_t   *r;
    ngx_lua_main_conf_t  *lmcf;

    thr = ngx_lua_thread(l);

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_session_ctx_t));

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_http_module);

    if (lmcf->session_mode == NGX_SESSION_MODE_SINGLE) {
        ngx_session_destroy(&lmcf->session, ctx);
    }

    /* TODO */
#endif

    return 0;
}


static int
ngx_lua_http_session_set_param(lua_State *l)
{
#if 0
    ngx_pool_t           *pool;
    ngx_session_ctx_t    *ctx;
    ngx_http_request_t   *r;
    ngx_lua_main_conf_t  *lmcf;

    thr = ngx_lua_thread(l);

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_session_ctx_t));

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_http_module);

    if (lmcf->session_mode == NGX_SESSION_MODE_SINGLE) {
        ngx_session_set_param(&lmcf->session, ctx);
    }

    /* TODO */
#endif

    return 0;
}


static int
ngx_lua_http_session_get_param(lua_State *l)
{
#if 0
    ngx_pool_t           *pool;
    ngx_session_ctx_t    *ctx;
    ngx_http_request_t   *r;
    ngx_lua_main_conf_t  *lmcf;

    thr = ngx_lua_thread(l);

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_session_ctx_t));

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_http_module);

    if (lmcf->session_mode == NGX_SESSION_MODE_SINGLE) {
        ngx_session_get_param(&lmcf->session, ctx);
    }

    /* TODO */
#endif

    return 0;
}


static int
ngx_lua_http_session_index(lua_State *l)
{
#if 0
    ngx_pool_t           *pool;
    ngx_session_ctx_t    *ctx;
    ngx_http_request_t   *r;
    ngx_lua_main_conf_t  *lmcf;

    thr = ngx_lua_thread(l);

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_session_ctx_t));

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_http_module);

    if (lmcf->session_mode == NGX_SESSION_MODE_SINGLE) {
        ngx_session_get_var(&lmcf->session, ctx);
    }

    /* TODO */
#endif

    return 0;
}


static int
ngx_lua_http_session_newindex(lua_State *l)
{
#if 0
    ngx_pool_t           *pool;
    ngx_lua_thread_t     *thr;
    ngx_session_ctx_t    *ctx;
    ngx_lua_main_conf_t  *lmcf;

    thr = ngx_lua_thread(l);

    pool = ngx_create_pool(ngx_pagesize, thr->log);
    if (pool == NULL) {
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_session_ctx_t));

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_http_module);

    if (lmcf->session_mode == NGX_SESSION_MODE_SINGLE) {
        ngx_session_set_var(&lmcf->session, ctx);

        ngx_session_del_var(&lmcf->session, ctx);
    }

    /* TODO */
#endif

    return 0;
}


static ngx_int_t
ngx_lua_http_session_module_init(ngx_cycle_t *cycle)
{
    int              n;
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "lua http session module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    lua_getglobal(lcf->l, NGX_LUA_TABLE);
    lua_getfield(lcf->l, -1, NGX_LUA_HTTP_TABLE);

    n = sizeof(ngx_lua_http_session_consts) / sizeof(ngx_lua_const_t) - 1;
    n += sizeof(ngx_lua_http_session_methods) / sizeof(luaL_Reg) - 1;

    lua_createtable(lcf->l, 0, n);

    for (n = 0; ngx_lua_http_session_consts[n].name != NULL; n++) {
        lua_pushinteger(lcf->l, ngx_lua_http_session_consts[n].value);
        lua_setfield(lcf->l, -2, ngx_lua_http_session_consts[n].name);
    }

    for (n = 0; ngx_lua_http_session_methods[n].name != NULL; n++) {
        lua_pushcfunction(lcf->l, ngx_lua_http_session_methods[n].func);
        lua_setfield(lcf->l, -2, ngx_lua_http_session_methods[n].name);
    }

    lua_createtable(lcf->l, 0, 2);
    lua_pushcfunction(lcf->l, ngx_lua_http_session_index);
    lua_setfield(lcf->l, -2, "__index");
    lua_pushcfunction(lcf->l, ngx_lua_http_session_newindex);
    lua_setfield(lcf->l, -2, "__newindex");
    lua_setmetatable(lcf->l, -2);

    lua_setfield(lcf->l, -2, "session");

    lua_pop(lcf->l, 2);

    return NGX_OK;
}
