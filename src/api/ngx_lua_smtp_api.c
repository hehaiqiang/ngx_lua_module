
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_module.h>


typedef struct ngx_lua_smtp_cleanup_ctx_s  ngx_lua_smtp_cleanup_ctx_t;


typedef struct {
    ngx_url_t                      u;
    ngx_str_t                      user;
    ngx_str_t                      passwd;
    ngx_str_t                      from;
    ngx_array_t                    to;
    ngx_str_t                      subject;
    ngx_str_t                      content;
    ngx_msec_t                     connect_timeout;
    ngx_msec_t                     send_timeout;
    ngx_msec_t                     read_timeout;
    ngx_pool_t                    *pool;
    ngx_peer_connection_t          peer;
    ngx_buf_t                     *request;
    ngx_buf_t                     *response;
    ngx_int_t                      rc;
    ngx_uint_t                     not_event;
    ngx_uint_t                     state;
    ngx_uint_t                     n;
    ngx_http_request_t            *r;
    ngx_lua_smtp_cleanup_ctx_t    *cln_ctx;
} ngx_lua_smtp_ctx_t;


struct ngx_lua_smtp_cleanup_ctx_s {
    ngx_lua_smtp_ctx_t            *ctx;
};


static ngx_int_t ngx_lua_smtp_parse_args(lua_State *l, ngx_http_request_t *r,
    ngx_lua_smtp_ctx_t *ctx);

static void ngx_lua_smtp_connect_handler(ngx_event_t *wev);
static void ngx_lua_smtp_write_handler(ngx_event_t *wev);
static void ngx_lua_smtp_read_handler(ngx_event_t *rev);
static void ngx_lua_smtp_dummy_handler(ngx_event_t *ev);

static ngx_int_t ngx_lua_smtp_handle_response(ngx_lua_smtp_ctx_t *ctx);

static void ngx_lua_smtp_finalize(ngx_lua_smtp_ctx_t *ctx, char *errstr);
static void ngx_lua_smtp_cleanup(void *data);


int
ngx_lua_smtp(lua_State *l)
{
    char                        *errstr;
    ngx_int_t                    rc;
    ngx_pool_t                  *pool;
    ngx_http_cleanup_t          *cln;
    ngx_http_request_t          *r;
    ngx_lua_smtp_ctx_t          *ctx;
    ngx_peer_connection_t       *peer;
    ngx_lua_smtp_cleanup_ctx_t  *cln_ctx;

    r = ngx_lua_request(l);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lua smtp");

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
        errstr = "ngx_create_pool() failed";
        goto error;
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_lua_smtp_ctx_t));
    if (ctx == NULL) {
        ngx_destroy_pool(pool);
        errstr = "ngx_pcalloc() failed";
        goto error;
    }

    ctx->pool = pool;

    if (ngx_array_init(&ctx->to, pool, 16, sizeof(ngx_str_t)) == NGX_ERROR) {
        ngx_destroy_pool(pool);
        errstr = "ngx_array_init() failed";
        goto error;
    }

    cln_ctx = ngx_pcalloc(r->pool, sizeof(ngx_lua_smtp_cleanup_ctx_t));
    if (cln_ctx == NULL) {
        ngx_destroy_pool(pool);
        errstr = "ngx_pcalloc() failed";
        goto error;
    }

    cln_ctx->ctx = ctx;

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        ngx_destroy_pool(pool);
        errstr = "ngx_http_cleanup_add() failed";
        goto error;
    }

    cln->handler = ngx_lua_smtp_cleanup;
    cln->data = cln_ctx;

    ctx->r = r;
    ctx->cln_ctx = cln_ctx;

    if (!lua_istable(l, 1)) {
        return luaL_error(l, "invalid the first argument, must be a table");
    }

    if (ngx_lua_smtp_parse_args(l, r, ctx) == NGX_ERROR) {
        return 2;
    }

    ctx->u.default_port = 25;
    ctx->u.one_addr = 1;

    if (ngx_parse_url(pool, &ctx->u) != NGX_OK) {
        if (ctx->u.err) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "%s in url \"%V\"", ctx->u.err, &ctx->u.url);
        }

        errstr = ctx->u.err;
        goto error;
    }

    peer = &ctx->peer;

    peer->sockaddr = ctx->u.addrs->sockaddr;
    peer->socklen = ctx->u.addrs->socklen;
    peer->name = &ctx->u.addrs->name;
    peer->get = ngx_event_get_peer;
    peer->log = ngx_cycle->log;
    peer->log_error = NGX_ERROR_ERR;
#if (NGX_THREADS)
    peer->lock = &r->connection->lock;
#endif

    rc = ngx_event_connect_peer(peer);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->connection->log, 0,
                   "lua smtp connecting to server: %i", rc);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        errstr = "ngx_event_connect_peer() failed";
        goto error;
    }

    peer->connection->data = ctx;
    peer->connection->pool = pool;

    peer->connection->read->handler = ngx_lua_smtp_dummy_handler;
    peer->connection->write->handler = ngx_lua_smtp_connect_handler;

    if (rc == NGX_AGAIN) {
        ngx_add_timer(peer->connection->write, ctx->connect_timeout);
        return lua_yield(l, 0);
    }

    /* rc == NGX_OK */

    ctx->rc = 0;
    ctx->not_event = 1;

    ngx_lua_smtp_connect_handler(peer->connection->write);

    ctx->not_event = 0;

    rc = ctx->rc;

    if (rc == NGX_AGAIN) {
        return lua_yield(l, 0);
    }

    cln_ctx->ctx = NULL;

    ngx_destroy_pool(ctx->pool);

    return rc;

error:

    lua_pushboolean(l, 0);
    lua_pushstring(l, errstr);

    return 2;
}


static ngx_int_t
ngx_lua_smtp_parse_args(lua_State *l, ngx_http_request_t *r,
    ngx_lua_smtp_ctx_t *ctx)
{
    char       *errstr;
    size_t      n, i;
    ngx_str_t   str, *to;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua smtp parse args");

    /* host */

    lua_getfield(l, 1, "host");
    str.data = (u_char *) luaL_checklstring(l, -1, &str.len);

    ctx->u.url.len = str.len;
    ctx->u.url.data = ngx_pstrdup(ctx->pool, &str);
    if (ctx->u.url.data == NULL) {
        errstr = "ngx_pstrdup() failed";
        goto error;
    }

    /* user */

    lua_getfield(l, 1, "user");
    str.data = (u_char *) luaL_checklstring(l, -1, &str.len);

    ctx->user.len = str.len;
    ctx->user.data = ngx_pstrdup(ctx->pool, &str);
    if (ctx->user.data == NULL) {
        errstr = "ngx_pstrdup() failed";
        goto error;
    }

    /* password */

    lua_getfield(l, 1, "password");
    str.data = (u_char *) luaL_checklstring(l, -1, &str.len);

    ctx->passwd.len = str.len;
    ctx->passwd.data = ngx_pstrdup(ctx->pool, &str);
    if (ctx->passwd.data == NULL) {
        errstr = "ngx_pstrdup() failed";
        goto error;
    }

    /* from */

    lua_getfield(l, 1, "from");
    str.data = (u_char *) luaL_checklstring(l, -1, &str.len);

    ctx->from.len = str.len;
    ctx->from.data = ngx_pstrdup(ctx->pool, &str);
    if (ctx->from.data == NULL) {
        errstr = "ngx_pstrdup() failed";
        goto error;
    }

    /* to */

    lua_getfield(l, 1, "to");
    if (!lua_istable(l, -1)) {
        return luaL_error(l,
                          "invalid value of the argument \"to\""
                          ", must be a table");
    }

    n = lua_objlen(l, -1);
    if (n == 0) {
        return luaL_error(l, "the argument \"to\" is an empty table");
    }

    for (i = 1; i <= n; i++) {
        to = ngx_array_push(&ctx->to);
        if (to == NULL) {
            errstr = "ngx_array_push() failed";
            goto error;
        }

        lua_rawgeti(l, -1, i);
        str.data = (u_char *) luaL_checklstring(l, -1, &str.len);

        to->len = str.len;
        to->data = ngx_pstrdup(ctx->pool, &str);
        if (to->data == NULL) {
            errstr = "ngx_pstrdup() failed";
            goto error;
        }

        lua_pop(l, 1);
    }

    /* subject */

    lua_getfield(l, 1, "subject");
    str.data = (u_char *) luaL_checklstring(l, -1, &str.len);

    ctx->subject.len = str.len;
    ctx->subject.data = ngx_pstrdup(ctx->pool, &str);
    if (ctx->subject.data == NULL) {
        errstr = "ngx_pstrdup() failed";
        goto error;
    }

    /* content */

    lua_getfield(l, 1, "content");
    str.data = (u_char *) luaL_checklstring(l, -1, &str.len);

    ctx->content.len = str.len;
    ctx->content.data = ngx_pstrdup(ctx->pool, &str);
    if (ctx->content.data == NULL) {
        errstr = "ngx_pstrdup() failed";
        goto error;
    }

    lua_pop(l, 7);

    ctx->connect_timeout = (ngx_msec_t) luaL_optnumber(l, 2, 60000);
    ctx->send_timeout = (ngx_msec_t) luaL_optnumber(l, 3, 60000);
    ctx->read_timeout = (ngx_msec_t) luaL_optnumber(l, 4, 60000);

    return NGX_OK;

error:

    lua_pushboolean(l, 0);
    lua_pushstring(l, errstr);

    return NGX_ERROR;
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
        ngx_lua_smtp_finalize(ctx, "ngx_lua_smtp_connect_handler() timed out");
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    c->read->handler = ngx_lua_smtp_read_handler;
    wev->handler = ngx_lua_smtp_dummy_handler;

    size = ngx_pagesize + ctx->subject.len + ctx->content.len;

    ctx->request = ngx_create_temp_buf(ctx->pool, size);
    if (ctx->request == NULL) {
        ngx_lua_smtp_finalize(ctx, "ngx_create_temp_buf() failed");
        return;
    }

    ctx->response = ngx_create_temp_buf(ctx->pool, ngx_pagesize);
    if (ctx->response == NULL) {
        ngx_lua_smtp_finalize(ctx, "ngx_create_temp_buf() failed");
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
        ngx_lua_smtp_finalize(ctx, "ngx_lua_smtp_write_handler() failed");
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

            c->read->handler = ngx_lua_smtp_read_handler;
            wev->handler = ngx_lua_smtp_dummy_handler;

            ctx->response->last = ctx->response->pos;

            ngx_lua_smtp_read_handler(c->read);
            return;
        }

        if (n == NGX_AGAIN) {
            ngx_add_timer(wev, ctx->send_timeout);
            ctx->rc = NGX_AGAIN;
            return;
        }

        /* n == NGX_ERROR || n == 0 */

        ngx_lua_smtp_finalize(ctx, "ngx_send() failed");
        return;
    }
}


static void
ngx_lua_smtp_read_handler(ngx_event_t *rev)
{
    ssize_t              n;
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
        ngx_lua_smtp_finalize(ctx, "ngx_lua_smtp_read_handler() timed out");
        return;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    b = ctx->response;

    while (1) {

        n = ngx_recv(c, b->last, b->end - b->last);

        if (n > 0) {
            b->last += n;

            rc = ngx_lua_smtp_handle_response(ctx);

            if (rc == NGX_OK) {
                return;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }

            if (rc == NGX_DONE) {
                ngx_lua_smtp_finalize(ctx, NULL);
                return;
            }

            /* rc == NGX_ERROR */

            ngx_lua_smtp_finalize(ctx, "ngx_lua_smtp_handle_response() failed");
            return;
        }

        if (n == NGX_AGAIN) {
            ngx_add_timer(rev, ctx->read_timeout);
            ctx->rc = NGX_AGAIN;
            return;
        }

        /* n == NGX_ERROR || n == 0 */

        ngx_lua_smtp_finalize(ctx, "ngx_recv() failed");
        return;
    }
}


static void
ngx_lua_smtp_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "lua smtp dummy handler");
}


static ngx_int_t
ngx_lua_smtp_handle_response(ngx_lua_smtp_ctx_t *ctx)
{
    u_char      *p, *last;
    ngx_str_t    dst, src, *to;
    ngx_buf_t   *b;
    ngx_uint_t   i;
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

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "lua smtp handle response");

    b = ctx->response;

    if (b->last - b->pos < 4) {
        return NGX_AGAIN;
    }

    if (*(b->last - 2) != CR || *(b->last - 1) != LF) {
        if (b->last == b->end) {
            *(b->last - 1) = '\0';
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
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

        to = ctx->to.elts;
        b->last = ngx_slprintf(b->pos, b->end, "RCPT TO:<%V>" CRLF,
                               &to[ctx->n++]);

        state = sw_to;
        break;

    case sw_to:
        if (p[0] != '2' || p[1] != '5' || p[2] != '0') {
            return NGX_ERROR;
        }

        if (ctx->n < ctx->to.nelts) {
            to = ctx->to.elts;
            b->last = ngx_slprintf(b->pos, b->end, "RCPT TO:<%V>" CRLF,
                                   &to[ctx->n++]);
            break;
        }

        b->last = ngx_cpymem(b->pos, "DATA" CRLF, sizeof("DATA" CRLF) - 1);

        state = sw_data;
        break;

    case sw_data:
        if (p[0] != '3' || p[1] != '5' || p[2] != '4') {
            return NGX_ERROR;
        }

        b->last = ngx_slprintf(b->pos, b->end, "Subject: %V" CRLF,
                               &ctx->subject);

        to = ctx->to.elts;
        for (i = 0; i < ctx->to.nelts; i++) {
            b->last = ngx_slprintf(b->last, b->end, "To: %V" CRLF, &to[i]);
        }

        b->last = ngx_slprintf(b->last, b->end, CRLF "%V" CRLF "." CRLF,
                               &ctx->content);

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

        return NGX_DONE;

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
ngx_lua_smtp_finalize(ngx_lua_smtp_ctx_t *ctx, char *errstr)
{
    ngx_int_t            rc;
    ngx_lua_ctx_t       *lua_ctx;
    ngx_http_request_t  *r;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "lua smtp finalize");

    if (ctx->cln_ctx != NULL) {
        ctx->cln_ctx->ctx = NULL;
    }

    r = ctx->r;

    if (r == NULL) {
        if (ctx->peer.connection) {
            ngx_close_connection(ctx->peer.connection);
        }

        ngx_destroy_pool(ctx->pool);
        return;
    }

    lua_ctx = ngx_http_get_module_ctx(r, ngx_lua_module);

    ctx->rc = 1;

    if (errstr == NULL) {
        lua_pushboolean(lua_ctx->l, 1);

    } else {
        lua_pushboolean(lua_ctx->l, 0);
        lua_pushstring(lua_ctx->l, errstr);

        ctx->rc++;
    }

    if (ctx->peer.connection) {
        ngx_close_connection(ctx->peer.connection);
    }

    if (ctx->not_event) {
        return;
    }

    rc = ctx->rc;

    ngx_destroy_pool(ctx->pool);

    rc = ngx_lua_thread_run(r, lua_ctx, rc);
    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_lua_finalize(r, rc);
}


static void
ngx_lua_smtp_cleanup(void *data)
{
    ngx_lua_smtp_cleanup_ctx_t *cln_ctx = data;

    ngx_lua_smtp_ctx_t  *ctx;

    ctx = cln_ctx->ctx;

    if (ctx != NULL) {
        ctx->r = NULL;
        ctx->cln_ctx = NULL;

        ngx_lua_smtp_finalize(ctx, NULL);
    }
}
