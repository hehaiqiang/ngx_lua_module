
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_btt_udp.h>
#include <ngx_lua_udp_module.h>


static ngx_int_t ngx_lua_udp_btt_module_init(ngx_cycle_t *cycle);


ngx_module_t  ngx_lua_udp_btt_module = {
    NGX_MODULE_V1,
    NULL,                                  /* module context */
    NULL,                                  /* module directives */
    NGX_UDP_MODULE,                        /* module type */
    NULL,                                  /* init master */
    ngx_lua_udp_btt_module_init,           /* init module */
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
        &ngx_lua_udp_btt_module,
        NULL
    };

    return modules;
}
#endif


static int
ngx_lua_udp_btt(lua_State *l)
{
    ngx_btt_ctx_t      *ctx;
    ngx_lua_thread_t   *thr;
    ngx_lua_udp_ctx_t  *uctx;
    ngx_udp_session_t  *s;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua udp btt");

    ctx = ngx_pcalloc(thr->pool, sizeof(ngx_btt_ctx_t));
    if (ctx == NULL) {
        lua_pushboolean(l, 0);
        return 1;
    }

    ctx->pool = thr->pool;
    ctx->log = thr->log;
    uctx = thr->module_ctx;
    s = uctx->s;

    if (ngx_btt_udp_handle_request(s, ctx) != NGX_OK) {
        lua_pushboolean(l, 0);
        return 1;
    }

    uctx->out = ngx_alloc_chain_link(ctx->pool);
    if (uctx->out == NULL) {
        lua_pushboolean(l, 0);
        return 1;
    }

    uctx->out->buf = ctx->response;
    uctx->out->next = NULL;

    uctx->last = uctx->out;

    lua_pushboolean(l, 1);

    return 1;
}


static ngx_int_t
ngx_lua_udp_btt_module_init(ngx_cycle_t *cycle)
{
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "lua udp btt module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    lua_getglobal(lcf->l, NGX_LUA_TABLE);
    lua_getfield(lcf->l, -1, NGX_LUA_UDP_TABLE);

    lua_pushcfunction(lcf->l, ngx_lua_udp_btt);
    lua_setfield(lcf->l, -2, "btt");

    lua_pop(lcf->l, 2);

    return NGX_OK;
}
