
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_btt_http.h>
#include <ngx_lua_http_module.h>


static ngx_int_t ngx_lua_http_btt_module_init(ngx_cycle_t *cycle);


ngx_module_t  ngx_lua_http_btt_module = {
    NGX_MODULE_V1,
    NULL,                                  /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_lua_http_btt_module_init,          /* init module */
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
        &ngx_lua_http_btt_module,
        NULL
    };

    return modules;
}
#endif


static int
ngx_lua_http_btt_announce(lua_State *l)
{
    ngx_btt_ctx_t       *ctx;
    ngx_lua_thread_t    *thr;
    ngx_lua_http_ctx_t  *hctx;
    ngx_http_request_t  *r;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, thr->log, 0, "lua http btt announce");

    ctx = ngx_pcalloc(thr->pool, sizeof(ngx_btt_ctx_t));
    if (ctx == NULL) {
        lua_pushboolean(l, 0);
        return 1;
    }

    ctx->pool = thr->pool;
    ctx->log = thr->log;
    hctx = thr->module_ctx;
    r = hctx->r;

    if (ngx_btt_http_handle_request(r, ctx) != NGX_OK) {
        lua_pushboolean(l, 0);
        return 1;
    }

    hctx->out = ngx_alloc_chain_link(ctx->pool);
    if (hctx->out == NULL) {
        lua_pushboolean(l, 0);
        return 1;
    }

    hctx->out->buf = ctx->response;
    hctx->out->next = NULL;

    hctx->last = hctx->out;

    lua_pushboolean(l, 1);

    return 1;
}


static ngx_int_t
ngx_lua_http_btt_module_init(ngx_cycle_t *cycle)
{
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "lua http btt module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    lua_getglobal(lcf->l, NGX_LUA_TABLE);
    lua_getfield(lcf->l, -1, NGX_LUA_HTTP_TABLE);

    lua_createtable(lcf->l, 0, 1);
    lua_pushcfunction(lcf->l, ngx_lua_http_btt_announce);
    lua_setfield(lcf->l, -2, "announce");
    lua_setfield(lcf->l, -2, "btt");

    lua_pop(lcf->l, 2);

    return NGX_OK;
}
