
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_udt_module.h>


static int ngx_lua_udt_response_send(lua_State *l);
static void ngx_lua_udt_response_write_handler(ngx_event_t *wev);
static void ngx_lua_udt_response_dummy_handler(ngx_event_t *ev);

static ngx_int_t ngx_lua_udt_response_module_init(ngx_cycle_t *cycle);


static luaL_Reg  ngx_lua_udt_response_methods[] = {
    { "send", ngx_lua_udt_response_send },
    { NULL, NULL }
};


ngx_module_t  ngx_lua_udt_response_module = {
    NGX_MODULE_V1,
    NULL,                                  /* module context */
    NULL,                                  /* module directives */
    NGX_UDT_MODULE,                        /* module type */
    NULL,                                  /* init master */
    ngx_lua_udt_response_module_init,      /* init module */
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
        &ngx_lua_udt_response_module,
        NULL
    };

    return modules;
}
#endif


static int
ngx_lua_udt_response_send(lua_State *l)
{
    char               *errstr;
    ngx_chain_t        *cl;
    ngx_connection_t   *c;
    ngx_lua_thread_t   *thr;
    ngx_lua_udt_ctx_t  *ctx;
    ngx_udt_session_t  *s;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua udt response send");

    ctx = thr->module_ctx;
    s = ctx->s;
    c = s->connection;

    /* TODO: the arguments in lua stack */

    cl = ctx->out;

    if (cl == NULL || cl->buf->last - cl->buf->pos == 0) {
        errstr = "no data";
        goto error;
    }

    c->read->handler = ngx_lua_udt_response_dummy_handler;
    c->write->handler = ngx_lua_udt_response_write_handler;

    c->sent = 0;

    ctx->rc = 0;
    ctx->not_event = 1;

    ngx_lua_udt_response_write_handler(c->write);

    ctx->not_event = 0;

    if (ctx->rc != NGX_AGAIN) {
        return ctx->rc;
    }

    return lua_yield(l, 0);

error:

    lua_pushboolean(l, 0);
    lua_pushstring(l, errstr);

    return 2;
}


static void
ngx_lua_udt_response_write_handler(ngx_event_t *wev)
{
    char               *errstr;
    ssize_t             n;
    ngx_int_t           rc;
    ngx_chain_t        *cl;
    ngx_connection_t   *c;
    ngx_lua_thread_t   *thr;
    ngx_lua_udt_ctx_t  *ctx;
    ngx_udt_session_t  *s;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, wev->log, 0,
                   "lua udt response write handler");

    c = wev->data;
    s = c->data;

    thr = ngx_udt_get_module_ctx(s, ngx_lua_udt_module);

    ctx = thr->module_ctx;
    errstr = NULL;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
                      "lua udt response write %V timed out", &c->addr_text);
        errstr = "ngx_lua_udt_response_write_handler() timed out";
        n = NGX_ERROR;
        goto done;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    while (1) {

        cl = c->send_chain(c, ctx->out, 0);

        if (cl == NGX_CHAIN_ERROR) {
            n = NGX_ERROR;
            break;
        }

        if (cl != NULL) {
            /* TODO */
            ngx_add_timer(wev, 60000);

            if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                errstr = "ngx_handle_write_event() failed";
                n = NGX_ERROR;
                goto done;
            }

            ctx->rc = NGX_AGAIN;
            return;
        }

        for (cl = ctx->out; cl != NULL; cl = cl->next) {
            cl->buf->pos = cl->buf->start;
            cl->buf->last = cl->buf->pos;
        }

        ctx->last = ctx->out;

        n = (ssize_t) c->sent;

        break;
    }

done:

    wev->handler = ngx_lua_udt_response_dummy_handler;

    ctx->rc = 1;

    if (n > 0) {
        lua_pushnumber(thr->l, (lua_Number) c->sent);

    } else {
        lua_pushboolean(thr->l, 0);

        if (errstr != NULL) {
            lua_pushstring(thr->l, errstr);

            ctx->rc++;
        }
    }

    if (ctx->not_event) {
        return;
    }

    rc = ngx_lua_thread_run(thr, ctx->rc);
    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_lua_finalize(thr, rc);
}


static void
ngx_lua_udt_response_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0,
                   "lua udt response dummy handler");
}


static ngx_int_t
ngx_lua_udt_response_module_init(ngx_cycle_t *cycle)
{
    int              n;
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "lua udt response module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    lua_getglobal(lcf->l, NGX_LUA_TABLE);
    lua_getfield(lcf->l, -1, NGX_LUA_UDT_TABLE);

    n = sizeof(ngx_lua_udt_response_methods) / sizeof(luaL_Reg) - 1;

    lua_createtable(lcf->l, 0, n);

    for (n = 0; ngx_lua_udt_response_methods[n].name != NULL; n++) {
        lua_pushcfunction(lcf->l, ngx_lua_udt_response_methods[n].func);
        lua_setfield(lcf->l, -2, ngx_lua_udt_response_methods[n].name);
    }

    lua_setfield(lcf->l, -2, "response");

    lua_pop(lcf->l, 2);

    return NGX_OK;
}
