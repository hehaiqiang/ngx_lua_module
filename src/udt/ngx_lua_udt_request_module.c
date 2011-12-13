
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_udt_module.h>


static int ngx_lua_udt_request_recv(lua_State *l);
static void ngx_lua_udt_request_read_handler(ngx_event_t *rev);
static void ngx_lua_udt_request_dummy_handler(ngx_event_t *ev);

static ngx_int_t ngx_lua_udt_request_module_init(ngx_cycle_t *cycle);


static luaL_Reg  ngx_lua_udt_request_methods[] = {
    { "recv", ngx_lua_udt_request_recv },
    { NULL, NULL }
};


ngx_module_t  ngx_lua_udt_request_module = {
    NGX_MODULE_V1,
    NULL,                                  /* module context */
    NULL,                                  /* module directives */
    NGX_UDT_MODULE,                        /* module type */
    NULL,                                  /* init master */
    ngx_lua_udt_request_module_init,       /* init module */
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
        &ngx_lua_udt_request_module,
        NULL
    };

    return modules;
}
#endif


static int
ngx_lua_udt_request_recv(lua_State *l)
{
    char               *errstr;
    size_t              size;
    ngx_buf_t          *b;
    ngx_connection_t   *c;
    ngx_lua_thread_t   *thr;
    ngx_lua_udt_ctx_t  *ctx;
    ngx_udt_session_t  *s;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua udt request recv");

    ctx = thr->module_ctx;
    s = ctx->s;
    c = s->connection;

    /* TODO: the arguments in lua stack */

    size = (size_t) luaL_optnumber(l, 1, ngx_pagesize);

    b = s->buffer;

    if (b == NULL || (size_t) (b->end - b->start) < size) {
        if (b != NULL && (size_t) (b->end - b->start) > c->pool->max) {
            ngx_pfree(c->pool, b->start);
        }

        size = ngx_max(ngx_pagesize, size);

        b = ngx_create_temp_buf(c->pool, size);
        if (b == NULL) {
            errstr = "ngx_create_temp_buf() failed";
            goto error;
        }

        s->buffer = b;
    }

    b->last = b->pos;

    c->read->handler = ngx_lua_udt_request_read_handler;
    c->write->handler = ngx_lua_udt_request_dummy_handler;

    ctx->rc = 0;
    ctx->not_event = 1;

    ngx_lua_udt_request_read_handler(c->read);

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
ngx_lua_udt_request_read_handler(ngx_event_t *rev)
{
    char               *errstr;
    ssize_t             n;
    ngx_int_t           rc;
    ngx_buf_t          *b;
    ngx_connection_t   *c;
    ngx_lua_thread_t   *thr;
    ngx_lua_udt_ctx_t  *ctx;
    ngx_udt_session_t  *s;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, rev->log, 0,
                   "lua udt request read handler");

    c = rev->data;
    s = c->data;

    thr = ngx_udt_get_module_ctx(s, ngx_lua_udt_module);

    ctx = thr->module_ctx;
    b = s->buffer;
    errstr = NULL;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, rev->log, NGX_ETIMEDOUT,
                      "lua udt request read %V timed out", &c->addr_text);
        errstr = "ngx_lua_udt_request_read_handler() timed out";
        n = NGX_ERROR;
        goto done;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    while (1) {

        n = c->recv(c, b->last, b->end - b->last);

        if (n > 0) {
            b->last += n;
            break;
        }

        if (n == NGX_AGAIN) {
            /* TODO */
            ngx_add_timer(rev, 60000);

            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                errstr = "ngx_handle_read_event() failed";
                n = NGX_ERROR;
                goto done;
            }

            ctx->rc = NGX_AGAIN;
            return;
        }

        /* n == NGX_ERROR || n == 0 */

        break;
    }

done:

    rev->handler = ngx_lua_udt_request_dummy_handler;

    ctx->rc = 1;

    if (n > 0) {
        lua_pushlstring(thr->l, (char *) b->pos, n);

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
ngx_lua_udt_request_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0,
                   "lua udt request dummy handler");
}


static ngx_int_t
ngx_lua_udt_request_module_init(ngx_cycle_t *cycle)
{
    int              n;
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "lua udt request module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    lua_getglobal(lcf->l, NGX_LUA_TABLE);
    lua_getfield(lcf->l, -1, NGX_LUA_UDT_TABLE);

    n = sizeof(ngx_lua_udt_request_methods) / sizeof(luaL_Reg) - 1;

    lua_createtable(lcf->l, 0, n);

    for (n = 0; ngx_lua_udt_request_methods[n].name != NULL; n++) {
        lua_pushcfunction(lcf->l, ngx_lua_udt_request_methods[n].func);
        lua_setfield(lcf->l, -2, ngx_lua_udt_request_methods[n].name);
    }

    lua_setfield(lcf->l, -2, "request");

    lua_pop(lcf->l, 2);

    return NGX_OK;
}
