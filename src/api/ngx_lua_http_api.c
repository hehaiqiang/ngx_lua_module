
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_module.h>


typedef struct ngx_lua_http_cleanup_ctx_s  ngx_lua_http_cleanup_ctx_t;


typedef struct {
    ngx_url_t                      u;
    ngx_str_t                      method;
    ngx_str_t                      version;
    ngx_array_t                    headers;
    ngx_str_t                      body;
    ngx_msec_t                     connect_timeout;
    ngx_msec_t                     send_timeout;
    ngx_msec_t                     read_timeout;
    ngx_pool_t                    *pool;
    ngx_peer_connection_t          peer;
    ngx_buf_t                     *request;
    ngx_buf_t                     *response;
    ngx_buf_t                     *header;
    u_char                        *body_start;
    ngx_int_t                      rc;
    ngx_uint_t                     not_event;
    ngx_http_request_t            *r;
    ngx_lua_http_cleanup_ctx_t    *cln_ctx;

    ngx_uint_t                     step;
    ngx_uint_t                     state;

    /* used to parse HTTP response */

    ngx_uint_t                     status_code;
    ngx_uint_t                     status_count;
    u_char                        *status_start;
    u_char                        *status_end;

    off_t                          content_length;

    ngx_uint_t                     invalid_header;

    ngx_uint_t                     header_hash;
    ngx_uint_t                     lowcase_index;
    u_char                         lowcase_header[NGX_HTTP_LC_HEADER_LEN];

    u_char                        *header_name_start;
    u_char                        *header_name_end;
    u_char                        *header_start;
    u_char                        *header_end;
} ngx_lua_http_ctx_t;


struct ngx_lua_http_cleanup_ctx_s {
    ngx_lua_http_ctx_t            *ctx;
};


static ngx_int_t ngx_lua_http_parse_args(lua_State *l, ngx_http_request_t *r,
    ngx_lua_http_ctx_t *ctx);

static void ngx_lua_http_connect_handler(ngx_event_t *wev);
static void ngx_lua_http_write_handler(ngx_event_t *wev);
static void ngx_lua_http_read_handler(ngx_event_t *rev);
static void ngx_lua_http_dummy_handler(ngx_event_t *ev);

static ngx_int_t ngx_lua_http_parse_status_line(ngx_lua_http_ctx_t *ctx);
static ngx_int_t ngx_lua_http_parse_header_line(ngx_lua_http_ctx_t *ctx);
static ngx_int_t ngx_lua_http_parse_headers(ngx_lua_http_ctx_t *ctx);
static ngx_int_t ngx_lua_http_parse_response(ngx_lua_http_ctx_t *ctx);

static void ngx_lua_http_finalize(ngx_lua_http_ctx_t *ctx, char *errstr);
static void ngx_lua_http_cleanup(void *data);


int
ngx_lua_http(lua_State *l)
{
    char                        *errstr;
    ngx_int_t                    rc;
    ngx_pool_t                  *pool;
    ngx_lua_http_ctx_t          *ctx;
    ngx_http_cleanup_t          *cln;
    ngx_http_request_t          *r;
    ngx_peer_connection_t       *peer;
    ngx_lua_http_cleanup_ctx_t  *cln_ctx;

    r = ngx_lua_request(l);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lua http");

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
        errstr = "ngx_create_pool() failed";
        goto error;
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_lua_http_ctx_t));
    if (ctx == NULL) {
        ngx_destroy_pool(pool);
        errstr = "ngx_pcalloc() failed";
        goto error;
    }

    if (ngx_array_init(&ctx->headers, pool, 16, sizeof(ngx_keyval_t)) != NGX_OK)
    {
        ngx_destroy_pool(pool);
        errstr = "ngx_array_init() failed";
        goto error;
    }

    ctx->pool = pool;

    cln_ctx = ngx_pcalloc(r->pool, sizeof(ngx_lua_http_cleanup_ctx_t));
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

    cln->handler = ngx_lua_http_cleanup;
    cln->data = cln_ctx;

    ctx->r = r;
    ctx->cln_ctx = cln_ctx;

    if (ngx_lua_http_parse_args(l, r, ctx) == NGX_ERROR) {
        return 2;
    }

    ctx->u.default_port = 80;
    ctx->u.one_addr = 1;
    ctx->u.uri_part = 1;

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
                   "lua http connecting to server: %i", rc);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        errstr = "ngx_event_connect_peer() failed";
        goto error;
    }

    peer->connection->data = ctx;
    peer->connection->pool = pool;

    peer->connection->read->handler = ngx_lua_http_dummy_handler;
    peer->connection->write->handler = ngx_lua_http_connect_handler;

    lua_createtable(l, 1, 3);
    lua_createtable(l, 0, 16);
    lua_setfield(l, -2, "headers");

    if (rc == NGX_AGAIN) {
        ngx_add_timer(peer->connection->write, ctx->connect_timeout);
        return lua_yield(l, 0);
    }

    /* rc == NGX_OK */

    ctx->rc = 0;
    ctx->not_event = 1;

    ngx_lua_http_connect_handler(peer->connection->write);

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
ngx_lua_http_parse_args(lua_State *l, ngx_http_request_t *r,
    ngx_lua_http_ctx_t *ctx)
{
    int            top;
    char          *errstr;
    u_char        *p, *last;
    ngx_str_t      str;
    ngx_keyval_t  *header;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua http parse args");

    if (!lua_istable(l, 1)) {
        return luaL_error(l, "invalid the first argument, must be a table");
    }

    top = lua_gettop(l);

    lua_getfield(l, 1, "method");
    str.data = (u_char *) luaL_optlstring(l, -1, "GET", &str.len);

    ctx->method.len = str.len;
    ctx->method.data = ngx_pstrdup(ctx->pool, &str);
    if (ctx->method.data == NULL) {
        errstr = "ngx_pstrdup() failed";
        goto error;
    }

    lua_getfield(l, 1, "version");
    str.data = (u_char *) luaL_optlstring(l, -1, "1.1", &str.len);

    ctx->version.len = str.len;
    ctx->version.data = ngx_pstrdup(ctx->pool, &str);
    if (ctx->version.data == NULL) {
        errstr = "ngx_pstrdup() failed";
        goto error;
    }

    lua_getfield(l, 1, "url");
    str.data = (u_char *) luaL_checklstring(l, -1, &str.len);

    ctx->u.url.len = str.len;
    ctx->u.url.data = ngx_pstrdup(ctx->pool, &str);
    if (ctx->u.url.data == NULL) {
        errstr = "ngx_pstrdup() failed";
        goto error;
    }

    lua_getfield(l, 1, "headers");
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
                errstr = "ngx_array_push() failed";
                goto error;
            }

            str.data = (u_char *) luaL_checklstring(l, -2, &str.len);

            header->key.len = str.len;
            header->key.data = ngx_pstrdup(ctx->pool, &str);

            header->key.data[0] = ngx_toupper(header->key.data[0]);

            for (p = header->key.data, last = p + header->key.len;
                 p < last - 1;
                 p++)
            {
                if (*p == '_') {
                    *p = '-';

                    p[1] = ngx_toupper(p[1]);
                }
            }

            str.data = (u_char *) luaL_checklstring(l, -1, &str.len);

            header->value.len = str.len;
            header->value.data = ngx_pstrdup(ctx->pool, &str);

            lua_pop(l, 1);
        }
    }

    lua_getfield(l, 1, "body");
    str.data = (u_char *) luaL_optlstring(l, -1, "", &str.len);

    ctx->body.len = str.len;
    ctx->body.data = ngx_pstrdup(ctx->pool, &str);
    if (ctx->body.data == NULL) {
        errstr = "ngx_pstrdup() failed";
        goto error;
    }

    lua_settop(l, top);

    ctx->connect_timeout = (ngx_msec_t) luaL_optnumber(l, 2, 60000);
    ctx->send_timeout = (ngx_msec_t) luaL_optnumber(l, 3, 60000);
    ctx->read_timeout = (ngx_msec_t) luaL_optnumber(l, 4, 60000);

    return NGX_OK;

error:

    lua_settop(l, top);
    lua_pushboolean(l, 0);
    lua_pushstring(l, errstr);

    return NGX_ERROR;
}


static void
ngx_lua_http_connect_handler(ngx_event_t *wev)
{
    size_t               size;
    ngx_buf_t           *b;
    ngx_uint_t           i;
    ngx_keyval_t        *headers;
    ngx_connection_t    *c;
    ngx_lua_http_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "lua http connect handler");

    c = wev->data;
    ctx = c->data;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
                      "lua http connecting %V timed out", ctx->peer.name);
        ngx_lua_http_finalize(ctx, "ngx_lua_http_connect_handler() timed out");
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    c->read->handler = ngx_lua_http_dummy_handler;
    wev->handler = ngx_lua_http_write_handler;

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

    b = ngx_create_temp_buf(ctx->pool, size);
    if (b == NULL) {
        ngx_lua_http_finalize(ctx, "ngx_create_temp_buf() failed");
        return;
    }

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

    ctx->request = b;

    ctx->response = ngx_create_temp_buf(ctx->pool, ngx_pagesize);
    if (ctx->response == NULL) {
        ngx_lua_http_finalize(ctx, "ngx_create_temp_buf() failed");
        return;
    }

    ngx_lua_http_write_handler(wev);
}


static void
ngx_lua_http_write_handler(ngx_event_t *wev)
{
    ssize_t              n, size;
    ngx_buf_t           *b;
    ngx_connection_t    *c;
    ngx_lua_http_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "lua http write handler");

    c = wev->data;
    ctx = c->data;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
                      "lua http write %V timed out", ctx->peer.name);
        ngx_lua_http_finalize(ctx, "ngx_lua_http_write_handler() timed out");
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

            c->read->handler = ngx_lua_http_read_handler;
            wev->handler = ngx_lua_http_dummy_handler;

            ngx_lua_http_read_handler(c->read);

            return;
        }

        if (n == NGX_AGAIN) {
            ngx_add_timer(wev, ctx->send_timeout);
            ctx->rc = NGX_AGAIN;
            return;
        }

        /* n == NGX_ERROR || n == 0 */

        ngx_lua_http_finalize(ctx, "ngx_send() failed");
        return;
    }
}


static void
ngx_lua_http_read_handler(ngx_event_t *rev)
{
    ssize_t              n;
    ngx_int_t            rc;
    ngx_buf_t           *b;
    ngx_connection_t    *c;
    ngx_lua_http_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "lua http read handler");

    c = rev->data;
    ctx = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, rev->log, NGX_ETIMEDOUT,
                      "lua http read %V timed out", ctx->peer.name);
        ngx_lua_http_finalize(ctx, "ngx_lua_http_read_handler() timed out");
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

            rc = ngx_lua_http_parse_response(ctx);

            if (rc == NGX_OK) {
                return;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }

            if (rc == NGX_DONE) {
                ngx_lua_http_finalize(ctx, NULL);
                return;
            }

            /* rc == NGX_ERROR */

            ngx_lua_http_finalize(ctx, "ngx_lua_http_parse_response() failed");
            return;
        }

        if (n == NGX_AGAIN) {
            ngx_add_timer(rev, ctx->read_timeout);
            ctx->rc = NGX_AGAIN;
            return;
        }

        /* n == NGX_ERROR || n == 0 */

        ngx_lua_http_finalize(ctx, "ngx_recv() failed");
        return;
    }
}


static void
ngx_lua_http_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "lua http dummy handler");
}


static ngx_int_t
ngx_lua_http_parse_status_line(ngx_lua_http_ctx_t *ctx)
{
    u_char  *p, ch;
    enum {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_status,
        sw_space_after_status,
        sw_status_text,
        sw_almost_done
    } state;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "lua http parse status line");

    state = ctx->state;

    for (p = ctx->response->pos; p < ctx->response->last; p++) {
        ch = *p;

        switch (state) {

        /* "HTTP/" */
        case sw_start:
            switch (ch) {
            case 'H':
                state = sw_H;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_H:
            switch (ch) {
            case 'T':
                state = sw_HT;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_HT:
            switch (ch) {
            case 'T':
                state = sw_HTT;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_HTT:
            switch (ch) {
            case 'P':
                state = sw_HTTP;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_HTTP:
            switch (ch) {
            case '/':
                state = sw_first_major_digit;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        /* the first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9') {
                return NGX_ERROR;
            }

            state = sw_major_digit;
            break;

        /* the major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            break;

        /* the first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            state = sw_minor_digit;
            break;

        /* the minor HTTP version or the end of the request line */
        case sw_minor_digit:
            if (ch == ' ') {
                state = sw_status;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            break;

        /* HTTP status code */
        case sw_status:
            if (ch == ' ') {
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            ctx->status_code = ctx->status_code * 10 + ch - '0';

            if (++ctx->status_count == 3) {
                state = sw_space_after_status;
                ctx->status_start = p - 2;
            }

            break;

        /* space or end of line */
        case sw_space_after_status:
            switch (ch) {
            case ' ':
                state = sw_status_text;
                break;
            case '.':                    /* IIS may send 403.1, 403.2, etc */
                state = sw_status_text;
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                return NGX_ERROR;
            }
            break;

        /* any text until end of line */
        case sw_status_text:
            switch (ch) {
            case CR:
                state = sw_almost_done;

                break;
            case LF:
                goto done;
            }
            break;

        /* end of status line */
        case sw_almost_done:
            ctx->status_end = p - 1;
            switch (ch) {
            case LF:
                goto done;
            default:
                return NGX_ERROR;
            }
        }
    }

    ctx->response->pos = p;

    ctx->state = state;

    return NGX_AGAIN;

done:

    ctx->response->pos = p + 1;

    if (ctx->status_end == NULL) {
        ctx->status_end = p;
    }

    ctx->state = sw_start;

    return NGX_OK;
}


static ngx_int_t
ngx_lua_http_parse_header_line(ngx_lua_http_ctx_t *ctx)
{
    u_char      c, ch, *p;
    ngx_uint_t  hash, i;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_ignore_line,
        sw_almost_done,
        sw_header_almost_done
    } state;

    /* the last '\0' is not needed because string is zero terminated */

    static u_char  lowcase[] =
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0-\0\0" "0123456789\0\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "lua http parse header line");

    state = ctx->state;
    hash = ctx->header_hash;
    i = ctx->lowcase_index;

    for (p = ctx->response->pos; p < ctx->response->last; p++) {
        ch = *p;

        switch (state) {

        /* first char */
        case sw_start:
            ctx->header_name_start = p;
            ctx->invalid_header = 0;

            switch (ch) {
            case CR:
                ctx->header_end = p;
                state = sw_header_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto header_done;
            default:
                state = sw_name;

                c = lowcase[ch];

                if (c) {
                    hash = ngx_hash(0, c);
                    ctx->lowcase_header[0] = c;
                    i = 1;
                    break;
                }

                ctx->invalid_header = 1;

                break;

            }
            break;

        /* header name */
        case sw_name:
            c = lowcase[ch];

            if (c) {
                hash = ngx_hash(hash, c);
                ctx->lowcase_header[i++] = c;
                i &= (NGX_HTTP_LC_HEADER_LEN - 1);
                break;
            }

            if (ch == '_') {
                hash = ngx_hash(hash, ch);
                ctx->lowcase_header[i++] = ch;
                i &= (NGX_HTTP_LC_HEADER_LEN - 1);
                break;
            }

            if (ch == ':') {
                ctx->header_name_end = p;
                state = sw_space_before_value;
                break;
            }

            if (ch == CR) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            }

            /* IIS may send the duplicate "HTTP/1.1 ..." lines */
            if (ch == '/'
                && p - ctx->header_name_start == 4
                && ngx_strncmp(ctx->header_name_start, "HTTP", 4) == 0)
            {
                state = sw_ignore_line;
                break;
            }

            ctx->invalid_header = 1;

            break;

        /* space* before header value */
        case sw_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            default:
                ctx->header_start = p;
                state = sw_value;
                break;
            }
            break;

        /* header value */
        case sw_value:
            switch (ch) {
            case ' ':
                ctx->header_end = p;
                state = sw_space_after_value;
                break;
            case CR:
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto done;
            }
            break;

        /* space* before end of header line */
        case sw_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                state = sw_value;
                break;
            }
            break;

        /* ignore header line */
        case sw_ignore_line:
            switch (ch) {
            case LF:
                state = sw_start;
                break;
            default:
                break;
            }
            break;

        /* end of header line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            case CR:
                break;
            default:
                return NGX_ERROR;
            }
            break;

        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return NGX_ERROR;
            }
        }
    }

    ctx->response->pos = p;

    ctx->state = state;
    ctx->header_hash = hash;
    ctx->lowcase_index = i;

    return NGX_AGAIN;

done:

    ctx->response->pos = p + 1;

    ctx->state = sw_start;
    ctx->header_hash = hash;
    ctx->lowcase_index = i;

    return NGX_OK;

header_done:

    ctx->response->pos = p + 1;

    ctx->state = sw_start;

    return NGX_DONE;
}


static ngx_int_t
ngx_lua_http_parse_headers(ngx_lua_http_ctx_t *ctx)
{
    u_char         *p, ch;
    ngx_int_t       rc;
    ngx_lua_ctx_t  *lua_ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "lua http parse headers");

    for ( ;; ) {

        rc = ngx_lua_http_parse_header_line(ctx);

        if (rc != NGX_OK) {
            return rc;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                      "header name:%*s value:%*s",
                       ctx->header_name_end - ctx->header_name_start,
                       ctx->header_name_start,
                       ctx->header_end - ctx->header_start,
                       ctx->header_start);

        /* TODO */

        if (ctx->content_length == 0
            && ngx_strncmp(ctx->header_name_start, "Content-Length",
                           sizeof("Content-Length") - 1)
               == 0)
        {
            ctx->content_length = ngx_atoof(ctx->header_start,
                                           ctx->header_end - ctx->header_start);
            if (ctx->content_length == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

        if (ctx->r == NULL) {
            continue;
        }

        for (p = ctx->header_name_start; p < ctx->header_name_end - 1; p++) {
            ch = *p;

            if (ch >= 'A' && ch <= 'Z') {
                ch |= 0x20;

            } else if (ch == '-') {
                ch = '_';
            }

            *p = ch;
        }

        *ctx->header_name_end = '\0';

        lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

        lua_getfield(lua_ctx->l, -1, "headers");
        lua_pushlstring(lua_ctx->l, (char *) ctx->header_start,
                        ctx->header_end - ctx->header_start);
        lua_setfield(lua_ctx->l, -2, (char *) ctx->header_name_start);
        lua_pop(lua_ctx->l, 1);
    }
}


static ngx_int_t
ngx_lua_http_parse_response(ngx_lua_http_ctx_t *ctx)
{
    size_t     size;
    ngx_int_t  rc;
    enum {
        sw_status_line = 0,
        sw_headers,
        sw_body
    } step;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "lua http parse response");

    step = ctx->step;

    for ( ;; ) {

        switch (step) {

        case sw_status_line:
            rc = ngx_lua_http_parse_status_line(ctx);
            if (rc == NGX_OK) {
                step = sw_headers;
            }

            break;

        case sw_headers:
            rc = ngx_lua_http_parse_headers(ctx);
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

        if (rc != NGX_OK) {
            break;
        }
    }

    ctx->step = step;

    return rc;
}


static void
ngx_lua_http_finalize(ngx_lua_http_ctx_t *ctx, char *errstr)
{
    ngx_int_t            rc;
    ngx_lua_ctx_t       *lua_ctx;
    ngx_http_request_t  *r;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "lua http finalize");

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

    } else {
        lua_pop(lua_ctx->l, 1);
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
ngx_lua_http_cleanup(void *data)
{
    ngx_lua_http_cleanup_ctx_t *cln_ctx = data;

    ngx_lua_http_ctx_t  *ctx;

    ctx = cln_ctx->ctx;

    if (ctx != NULL) {
        ctx->r = NULL;
        ctx->cln_ctx = NULL;

        ngx_lua_http_finalize(ctx, NULL);
    }
}
