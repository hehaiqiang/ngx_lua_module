
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_module.h>


typedef struct {
    ngx_str_t                 host;
    ngx_str_t                 user;
    ngx_str_t                 passwd;
    ngx_str_t                 from;
    ngx_array_t               to;
    ngx_str_t                 subject;
    ngx_str_t                 content;

    ngx_pool_t               *pool;
    ngx_peer_connection_t     peer;
    ngx_url_t                 u;
    ngx_buf_t                *request;
    ngx_buf_t                *response;
    ngx_msec_t                connect_timeout;
    ngx_msec_t                send_timeout;
    ngx_msec_t                read_timeout;
    ngx_int_t                 rc;
    ngx_uint_t                not_event;
    ngx_http_request_t       *r;
    ngx_uint_t                state;
} ngx_lua_smtp_ctx_t;


static void ngx_lua_smtp_connect_handler(ngx_event_t *wev);
static void ngx_lua_smtp_write_handler(ngx_event_t *wev);
static void ngx_lua_smtp_read_handler(ngx_event_t *rev);
static void ngx_lua_smtp_dummy_handler(ngx_event_t *ev);
static ngx_int_t ngx_lua_smtp_handle_response(ngx_http_request_t *r,
    ngx_lua_smtp_ctx_t *ctx);
static void ngx_lua_smtp_finalize(ngx_lua_smtp_ctx_t *ctx, ngx_int_t rc);
static void ngx_lua_smtp_cleanup(void *data);


int
ngx_lua_smtp(lua_State *l)
{
    size_t               n, i;
    ngx_int_t            rc;
    ngx_str_t            str, *to;
    ngx_pool_t          *pool;
    ngx_lua_smtp_ctx_t  *ctx;
    ngx_http_cleanup_t  *cln;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lua smtp");

    if (!lua_istable(l, -1)) {
        return luaL_error(l, "invalid argument, must be a table");
    }

    pool = ngx_create_pool(ngx_pagesize, r->connection->log);
    if (pool == NULL) {
        return luaL_error(l, "ngx_create_pool() failed");
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_lua_smtp_ctx_t));
    if (ctx == NULL) {
        ngx_destroy_pool(pool);
        return luaL_error(l, "ngx_pcalloc() failed");
    }

    if (ngx_array_init(&ctx->to, pool, 16, sizeof(ngx_str_t)) != NGX_OK) {
        ngx_destroy_pool(pool);
        return luaL_error(l, "ngx_array_init() failed");
    }

    /* TODO: connect_timeout, send_timeout and read_timeout */

    ctx->pool = pool;
    ctx->connect_timeout = 60000;
    ctx->send_timeout = 60000;
    ctx->read_timeout = 60000;
    ctx->r = r;

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        ngx_destroy_pool(pool);
        return luaL_error(l, "ngx_http_cleanup_add() failed");
    }

    cln->handler = ngx_lua_smtp_cleanup;
    cln->data = ctx;

    /* TODO: lua_pop() */

    lua_getfield(l, -1, "host");
    str.data = (u_char *) luaL_checklstring(l, -1, &str.len);

    ctx->host.len = str.len;
    ctx->host.data = ngx_pstrdup(pool, &str);
    if (ctx->host.data == NULL) {
        return luaL_error(l, "ngx_pstrdup() failed");
    }

    lua_getfield(l, -2, "user");
    str.data = (u_char *) luaL_checklstring(l, -1, &str.len);

    ctx->user.len = str.len;
    ctx->user.data = ngx_pstrdup(pool, &str);
    if (ctx->user.data == NULL) {
        return luaL_error(l, "ngx_pstrdup() failed");
    }

    lua_getfield(l, -3, "password");
    str.data = (u_char *) luaL_checklstring(l, -1, &str.len);

    ctx->passwd.len = str.len;
    ctx->passwd.data = ngx_pstrdup(pool, &str);
    if (ctx->passwd.data == NULL) {
        return luaL_error(l, "ngx_pstrdup() failed");
    }

    lua_getfield(l, -4, "from");
    str.data = (u_char *) luaL_checklstring(l, -1, &str.len);

    ctx->from.len = str.len;
    ctx->from.data = ngx_pstrdup(pool, &str);
    if (ctx->from.data == NULL) {
        return luaL_error(l, "ngx_pstrdup() failed");
    }

    lua_getfield(l, -5, "to");
    if (!lua_istable(l, -1)) {
        return luaL_error(l,
                          "invalid value of the argument \"to\""
                          ", must be a table");
    }

    n = lua_objlen(l, -1);

    for (i = 1; i <= n; i++) {
        to = ngx_array_push(&ctx->to);
        if (to == NULL) {
            return luaL_error(l, "ngx_array_push() failed");
        }

        lua_rawgeti(l, -1, i);
        str.data = (u_char *) luaL_checklstring(l, -1, &str.len);

        to->len = str.len;
        to->data = ngx_pstrdup(pool, &str);

        lua_pop(l, 1);
    }

    lua_getfield(l, -6, "subject");
    str.data = (u_char *) luaL_checklstring(l, -1, &str.len);

    ctx->subject.len = str.len;
    ctx->subject.data = ngx_pstrdup(pool, &str);
    if (ctx->subject.data == NULL) {
        return luaL_error(l, "ngx_pstrdup() failed");
    }

    lua_getfield(l, -7, "content");
    str.data = (u_char *) luaL_checklstring(l, -1, &str.len);

    ctx->content.len = str.len;
    ctx->content.data = ngx_pstrdup(pool, &str);
    if (ctx->content.data == NULL) {
        return luaL_error(l, "ngx_pstrdup() failed");
    }

    lua_pop(l, 7);

    ctx->u.url = ctx->host;
    ctx->u.default_port = 25;
    ctx->u.one_addr = 1;

    if (ngx_parse_url(pool, &ctx->u) != NGX_OK) {
        if (ctx->u.err) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "%s in url \"%V\"", ctx->u.err, &ctx->u.url);
        }

        lua_pushnumber(l, NGX_ERROR);

        return 1;
    }

    ctx->peer.sockaddr = ctx->u.addrs->sockaddr;
    ctx->peer.socklen = ctx->u.addrs->socklen;
    ctx->peer.name = &ctx->u.addrs->name;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.log = r->connection->log;
    ctx->peer.log_error = NGX_ERROR_ERR;
#if (NGX_THREADS)
    ctx->peer.lock = &r->connection->lock;
#endif

    rc = ngx_event_connect_peer(&ctx->peer);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->connection->log, 0,
                   "lua http connecting to server: %i", rc);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        lua_pushnumber(l, NGX_ERROR);
        return 1;
    }

    ctx->peer.connection->data = ctx;
    ctx->peer.connection->pool = pool;

    ctx->peer.connection->read->handler = ngx_lua_smtp_dummy_handler;
    ctx->peer.connection->write->handler = ngx_lua_smtp_connect_handler;

    if (rc == NGX_OK) {
        ctx->rc = 0;
        ctx->not_event = 1;

        ngx_lua_smtp_connect_handler(ctx->peer.connection->write);

        ctx->not_event = 0;

        /* TODO */

        if (ctx->rc != NGX_AGAIN) {
            lua_pushnumber(l, ctx->rc);
            return 1;
        }

        return lua_yield(l, 0);
    }

    /* rc == NGX_AGAIN */

    ngx_add_timer(ctx->peer.connection->write, ctx->connect_timeout);

    return lua_yield(l, 0);
}


static void
ngx_lua_smtp_connect_handler(ngx_event_t *wev)
{
    size_t               size;
    ngx_connection_t    *c;
    ngx_lua_smtp_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "lua smtp connect handler");

    c = wev->data;
    ctx = c->data;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
                      "lua smtp connecting %V timed out", ctx->peer.name);
        ngx_lua_smtp_finalize(ctx, NGX_ERROR);
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    c->read->handler = ngx_lua_smtp_read_handler;
    wev->handler = ngx_lua_smtp_dummy_handler;

    size = ctx->subject.len + ctx->content.len + ngx_pagesize;

    ctx->request = ngx_create_temp_buf(ctx->pool, size);
    if (ctx->request == NULL) {
        ngx_lua_smtp_finalize(ctx, NGX_ERROR);
        return;
    }

    ctx->response = ngx_create_temp_buf(ctx->pool, ngx_pagesize);
    if (ctx->response == NULL) {
        ngx_lua_smtp_finalize(ctx, NGX_ERROR);
        return;
    }

    ngx_lua_smtp_read_handler(wev);
}


static void
ngx_lua_smtp_write_handler(ngx_event_t *wev)
{
    ssize_t              n, size;
    ngx_buf_t           *b;
    ngx_connection_t    *c;
    ngx_lua_smtp_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "lua smtp write handler");

    c = wev->data;
    ctx = c->data;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
                      "lua smtp write %V timed out", ctx->peer.name);
        ngx_lua_smtp_finalize(ctx, NGX_ERROR);
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    b = ctx->request;

    while (1) {

        size = b->last - b->pos;

        n = ngx_send(c, b->pos, size);

        if (n > 0) {
            b->pos += n;

            if (n < size) {
                continue;
            }

            /* n == size */

            ctx->response->last = ctx->response->pos;

            c->read->handler = ngx_lua_smtp_read_handler;
            wev->handler = ngx_lua_smtp_dummy_handler;

            ngx_lua_smtp_read_handler(c->read);

            return;
        }

        if (n == NGX_AGAIN) {
            ngx_add_timer(wev, ctx->send_timeout);
            ctx->rc = NGX_AGAIN;
            return;
        }

        /* n == NGX_ERROR || n == 0 */

        ngx_lua_smtp_finalize(ctx, NGX_ERROR);

        return;
    }
}


static void
ngx_lua_smtp_read_handler(ngx_event_t *rev)
{
    ssize_t              n, size;
    ngx_int_t            rc;
    ngx_buf_t           *b;
    ngx_connection_t    *c;
    ngx_lua_smtp_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "lua smtp read handler");

    c = rev->data;
    ctx = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, rev->log, NGX_ETIMEDOUT,
                      "lua smtp read %V timed out", ctx->peer.name);
        ngx_lua_smtp_finalize(ctx, NGX_ERROR);
        return;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    b = ctx->response;

    while (1) {

        size = b->end - b->last;

        n = ngx_recv(c, b->last, size);

        if (n > 0) {
            b->last += n;

            rc = ngx_lua_smtp_handle_response(ctx->r, ctx);

            if (rc == NGX_AGAIN) {
                continue;
            }

            if (rc == NGX_ERROR) {
                ngx_lua_smtp_finalize(ctx, NGX_ERROR);
            }

            return;
        }

        if (n == NGX_AGAIN) {
            ngx_add_timer(rev, ctx->read_timeout);
            ctx->rc = NGX_AGAIN;
            return;
        }

        /* n == NGX_ERROR || n == 0 */

        ngx_lua_smtp_finalize(ctx, NGX_ERROR);

        return;
    }
}


static void
ngx_lua_smtp_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "lua smtp dummy handler");
}


static ngx_int_t
ngx_lua_smtp_handle_response(ngx_http_request_t *r, ngx_lua_smtp_ctx_t *ctx)
{
    u_char     *p, *last;
    ngx_str_t   dst, src;
    ngx_buf_t  *b;
    enum {
        sw_start = 0,
        sw_helo,
        sw_login,
        sw_user,
        sw_passwd,
        sw_from,
        sw_to,
        sw_data,
        sw_quit,
        sw_done
    } state;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua smtp handle response");

    b = ctx->response;

    if (b->last - b->pos < 4) {
        return NGX_AGAIN;
    }

    if (*(b->last - 2) != CR || *(b->last - 1) != LF) {
        if (b->last == b->end) {
            *(b->last - 1) = '\0';
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "stmp server sent too long response line: \"%s\"",
                          b->pos);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    p = b->pos;
    last = b->last;

    b = ctx->request;
    b->pos = b->start;

    state = ctx->state;

    switch (state) {

    case sw_start:
        if (p[0] != '2' || p[1] != '2' || p[2] != '0') {
            return NGX_ERROR;
        }

        b->last = ngx_slprintf(b->pos, b->end, "HELO %V" CRLF, &ctx->u.host);

        state = sw_helo;
        break;

    case sw_helo:
        if (p[0] != '2' || p[1] != '5' || p[2] != '0') {
            return NGX_ERROR;
        }

        b->last = ngx_cpymem(b->pos, "AUTH LOGIN" CRLF,
                             sizeof("AUTH LOGIN" CRLF) - 1);

        state = sw_login;
        break;

    case sw_login:
        if (p[0] != '3' || p[1] != '3' || p[2] != '4') {
            return NGX_ERROR;
        }

        src = ctx->user;

        dst.len = ngx_base64_encoded_length(src.len);
        dst.data = ngx_pnalloc(ctx->pool, dst.len);
        if (dst.data == NULL) {
            return NGX_ERROR;
        }

        ngx_encode_base64(&dst, &src);

        b->last = ngx_slprintf(b->pos, b->end, "%V" CRLF, &dst);

        state = sw_user;
        break;

    case sw_user:
        if (p[0] != '3' || p[1] != '3' || p[2] != '4') {
            return NGX_ERROR;
        }

        src = ctx->passwd;

        dst.len = ngx_base64_encoded_length(src.len);
        dst.data = ngx_pnalloc(ctx->pool, dst.len);
        if (dst.data == NULL) {
            return NGX_ERROR;
        }

        ngx_encode_base64(&dst, &src);

        b->last = ngx_slprintf(b->pos, b->end, "%V" CRLF, &dst);

        state = sw_passwd;
        break;

    case sw_passwd:
        if (p[0] != '2' || p[1] != '3' || p[2] != '5') {
            return NGX_ERROR;
        }

        b->last = ngx_slprintf(b->pos, b->end, "MAIL FROM:<%V>" CRLF,
                               &ctx->from);

        state = sw_from;
        break;

    case sw_from:
        if (p[0] != '2' || p[1] != '5' || p[2] != '0') {
            return NGX_ERROR;
        }

        /* TODO */

        b->last = ngx_slprintf(b->pos, b->end,
                               "RCPT TO:<184815157@qq.com>" CRLF);

        state = sw_to;
        break;

    case sw_to:
        if (p[0] != '2' || p[1] != '5' || p[2] != '0') {
            return NGX_ERROR;
        }

        b->last = ngx_cpymem(b->pos, "DATA" CRLF, sizeof("DATA" CRLF) - 1);

        state = sw_data;
        break;

    case sw_data:
        if (p[0] != '3' || p[1] != '5' || p[2] != '4') {
            return NGX_ERROR;
        }

        /* TODO */

        b->last = ngx_slprintf(b->pos, b->end,
                               "Subject: %V" CRLF
                               "To: 184815157@qq.com" CRLF
                               CRLF
                               "%V" CRLF "." CRLF,
                               &ctx->subject, &ctx->content);

        state = sw_quit;
        break;

    case sw_quit:
        if (p[0] != '2' || p[1] != '5' || p[2] != '0') {
            return NGX_ERROR;
        }

        b->last = ngx_cpymem(b->pos, "QUIT" CRLF, sizeof("QUIT" CRLF) - 1);

        state = sw_done;
        break;

    case sw_done:
        if (p[0] != '2' || p[1] != '2' || p[2] != '1') {
            return NGX_ERROR;
        }

        /* TODO */

        ngx_lua_smtp_finalize(ctx, NGX_OK);

        return NGX_OK;

    default:
        return NGX_ERROR;
    }

    ctx->state = state;

    ctx->peer.connection->read->handler = ngx_lua_smtp_dummy_handler;
    ctx->peer.connection->write->handler = ngx_lua_smtp_write_handler;

    ngx_lua_smtp_write_handler(ctx->peer.connection->write);

    return NGX_OK;
}


static void
ngx_lua_smtp_finalize(ngx_lua_smtp_ctx_t *ctx, ngx_int_t rc)
{
    ngx_lua_ctx_t  *lua_ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->r->connection->log, 0,
                   "lua smtp finalize");

    lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

    lua_pushnumber(lua_ctx->l, rc);

    if (ctx->not_event) {
        return;
    }

    rc = ngx_lua_thread_run(ctx->r, lua_ctx, 1);
    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_lua_finalize(ctx->r, rc);
}


static void
ngx_lua_smtp_cleanup(void *data)
{
    ngx_lua_smtp_ctx_t *ctx = data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->r->connection->log, 0,
                   "lua smtp cleanup");

    if (ctx->peer.connection) {
        ngx_close_connection(ctx->peer.connection);
    }

    ngx_destroy_pool(ctx->pool);
}
