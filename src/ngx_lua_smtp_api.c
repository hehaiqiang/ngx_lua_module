
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_module.h>


typedef struct {
    ngx_pool_t               *pool;
    ngx_str_t                 host;
    ngx_array_t               headers;
    ngx_str_t                 body;
    ngx_url_t                 u;
    ngx_peer_connection_t     peer;
    ngx_buf_t                *request;
    ngx_buf_t                *response;
    ngx_buf_t                *header;
    u_char                   *body_start;
    ngx_msec_t                connect_timeout;
    ngx_msec_t                send_timeout;
    ngx_msec_t                read_timeout;
    ngx_int_t                 rc;
    ngx_uint_t                not_event;
    ngx_http_request_t       *r;

    ngx_uint_t                step;
    ngx_uint_t                state;

    /* used to parse HTTP response */

    ngx_uint_t                status_code;
    ngx_uint_t                status_count;
    u_char                   *status_start;
    u_char                   *status_end;

    off_t                     content_length;

    ngx_uint_t                invalid_header;

    ngx_uint_t                header_hash;
    ngx_uint_t                lowcase_index;
    u_char                    lowcase_header[NGX_HTTP_LC_HEADER_LEN];

    u_char                   *header_name_start;
    u_char                   *header_name_end;
    u_char                   *header_start;
    u_char                   *header_end;
} ngx_lua_smtp_ctx_t;


static void ngx_lua_smtp_connect_handler(ngx_event_t *wev);
static void ngx_lua_smtp_write_handler(ngx_event_t *wev);
static void ngx_lua_smtp_read_handler(ngx_event_t *rev);
static void ngx_lua_smtp_dummy_handler(ngx_event_t *ev);
static ngx_int_t ngx_lua_smtp_parse_response(ngx_http_request_t *r,
    ngx_lua_smtp_ctx_t *ctx);
static void ngx_lua_smtp_finalize(ngx_lua_smtp_ctx_t *ctx, ngx_int_t rc);
static void ngx_lua_smtp_cleanup(void *data);


int
ngx_lua_smtp(lua_State *l)
{
    u_char              *p, *last;
    ngx_int_t            rc;
    ngx_str_t            str;
    ngx_pool_t          *pool;
    ngx_keyval_t        *header;
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

    if (ngx_array_init(&ctx->headers, pool, 16, sizeof(ngx_keyval_t)) != NGX_OK)
    {
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

    lua_getfield(l, -2, "headers");
    if (!lua_isnil(l, -1)) {
        if (!lua_istable(l, -1)) {
            return luaL_error(l,
                              "invalid value of the argument \"headers\""
                              ", must be a table");
        }

        lua_pushnil(l);
        while (lua_next(l, -2)) {
            header = ngx_array_push(&ctx->headers);
            if (header == NULL) {
                return luaL_error(l, "ngx_array_push() failed");
            }

            str.data = (u_char *) luaL_checklstring(l, -2, &str.len);

            header->key.len = str.len;
            header->key.data = ngx_pstrdup(pool, &str);

            for (p = header->key.data, last = p + header->key.len;
                 p < last - 1;
                 p++)
            {
                if (*p == '_') {
                    *p = '-';
                }
            }

            str.data = (u_char *) luaL_checklstring(l, -1, &str.len);

            header->value.len = str.len;
            header->value.data = ngx_pstrdup(pool, &str);

            lua_pop(l, 1);
        }
    }

    lua_getfield(l, -3, "body");
    str.data = (u_char *) luaL_optlstring(l, -1, "", &str.len);

    ctx->body.len = str.len;
    ctx->body.data = ngx_pstrdup(pool, &str);
    if (ctx->body.data == NULL) {
        return luaL_error(l, "ngx_pstrdup() failed");
    }

    /* TODO */
    lua_pop(l, 3);

    lua_createtable(l, 1, 4);
    lua_createtable(l, 0, 16);
    lua_setfield(l, -2, "headers");

    ctx->u.url = ctx->host;
    ctx->u.default_port = 25;
    ctx->u.one_addr = 1;

    if (ngx_parse_url(pool, &ctx->u) != NGX_OK) {
        if (ctx->u.err) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "%s in url \"%V\"", ctx->u.err, &ctx->u.url);
        }

        lua_pushnumber(l, NGX_ERROR);
        lua_setfield(l, -2, "status");

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
        lua_setfield(l, -2, "status");
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

        if (ctx->rc != NGX_AGAIN) {
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
    ngx_buf_t           *b;
#if 0
    ngx_uint_t           i;
    ngx_keyval_t        *headers;
#endif
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

    wev->handler = ngx_lua_smtp_write_handler;

#if 0
    size = ctx->method.len + 1 + ctx->u.uri.len + 6 + ctx->version.len + 2
           + sizeof("Host: ") - 1 + ctx->u.host.len + 1 + NGX_INT32_LEN + 2;

    headers = ctx->headers.elts;
    for (i = 0; i < ctx->headers.nelts; i++) {
        size += headers[i].key.len + 2 + headers[i].value.len + 2;
    }

    if (ctx->body.len) {
        size += sizeof("Content-Length: ") - 1 + NGX_INT32_LEN + 2;
    }

    size += 2 + ctx->body.len;
#else
    size = ngx_pagesize;
#endif

    b = ngx_create_temp_buf(ctx->pool, size);
    if (b == NULL) {
        ngx_lua_smtp_finalize(ctx, NGX_ERROR);
        return;
    }

#if 0
    b->last = ngx_slprintf(b->last, b->end, "%V %V HTTP/%V" CRLF,
                           &ctx->method, &ctx->u.uri, &ctx->version);
    b->last = ngx_slprintf(b->last, b->end, "Host: %V:%d" CRLF,
                           &ctx->u.host, (int) ctx->u.port);

    for (i = 0; i < ctx->headers.nelts; i++) {
        b->last = ngx_slprintf(b->last, b->end, "%V: %V" CRLF,
                               &headers[i].key, &headers[i].value);
    }

    if (ctx->body.len) {
        b->last = ngx_slprintf(b->last, b->end, "Content-Length: %uz" CRLF,
                               ctx->body.len);
    }

    *b->last++ = CR;
    *b->last++ = LF;

    if (ctx->body.len) {
        b->last = ngx_cpymem(b->last, ctx->body.data, ctx->body.len);
    }
#endif

    ctx->request = b;

    ctx->response = ngx_create_temp_buf(ctx->pool, ngx_pagesize);
    if (ctx->response == NULL) {
        ngx_lua_smtp_finalize(ctx, NGX_ERROR);
        return;
    }

    ngx_lua_smtp_write_handler(wev);
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

            if (ngx_lua_smtp_parse_response(ctx->r, ctx) == NGX_AGAIN) {
                continue;
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
ngx_lua_smtp_parse_response(ngx_http_request_t *r, ngx_lua_smtp_ctx_t *ctx)
{
#if 0
    size_t          size;
    ngx_int_t       rc;
    ngx_lua_ctx_t  *lua_ctx;
    enum {
        sw_status_line = 0,
        sw_headers,
        sw_body
    } step;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua smtp parse response");

    step = ctx->step;

    for ( ;; ) {

        switch (step) {

        case sw_status_line:
            rc = ngx_lua_http_parse_status_line(r, ctx);
            if (rc == NGX_OK) {
                step = sw_headers;
            }

            break;

        case sw_headers:
            rc = ngx_lua_http_parse_headers(r, ctx);
            if (rc == NGX_DONE) {
                rc = NGX_OK;
                ctx->body_start = ctx->response->pos;
                step = sw_body;
            }

            break;

        case sw_body:
            if (ctx->content_length > 0) {
                size = ctx->response->last - ctx->response->pos;
                ctx->response->pos = ctx->response->last;
                ctx->content_length -= size;
            }

            if (ctx->content_length > 0) {
                size = ctx->response->end - ctx->response->last;

                if (ctx->content_length > size) {
                    ctx->header = ctx->response;

                    ctx->response = ngx_create_temp_buf(ctx->pool,
                                                  (size_t) ctx->content_length);
                    if (ctx->response == NULL) {
                        rc = NGX_ERROR;
                        break;
                    }
                }

                rc = NGX_AGAIN;

            } else {
                rc = NGX_DONE;
            }

            break;

        default:
            rc = NGX_ERROR;
            break;
        }

        if (rc == NGX_AGAIN) {
            ctx->step = step;
            return rc;
        }

        if (rc != NGX_OK) {
            break;
        }
    }

    ctx->step = step;

    lua_ctx = ngx_http_get_module_ctx(r, ngx_lua_module);

    if (rc == NGX_ERROR) {
        lua_pushnumber(lua_ctx->l, NGX_ERROR);
        lua_setfield(lua_ctx->l, -2, "status");

        ngx_lua_http_finalize(ctx, rc);

        return rc;
    }

    lua_pushnumber(lua_ctx->l, ctx->status_code);
    lua_setfield(lua_ctx->l, -2, "status");

    if (ctx->header == NULL) {
        lua_pushlstring(lua_ctx->l, (char *) ctx->body_start,
                        ctx->response->last - ctx->body_start);

    } else {
        lua_pushlstring(lua_ctx->l, (char *) ctx->body_start,
                        ctx->header->last - ctx->body_start);
        lua_pushlstring(lua_ctx->l, (char *) ctx->response->start,
                        ctx->response->last - ctx->response->start);
        lua_concat(lua_ctx->l, 2);
    }

    lua_setfield(lua_ctx->l, -2, "body");

    ngx_lua_http_finalize(ctx, rc);
#endif

    return NGX_DONE;
}


static void
ngx_lua_smtp_finalize(ngx_lua_smtp_ctx_t *ctx, ngx_int_t rc)
{
    ngx_lua_ctx_t  *lua_ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->r->connection->log, 0,
                   "lua smtp finalize");

    if (ctx->not_event) {
        return;
    }

    lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

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
