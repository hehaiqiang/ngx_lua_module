
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_module.h>


#define NGX_LUA_SOCKET  "ngx_lua_socket_ctx_t*"


typedef struct {
    ngx_pool_t               *pool;
    ngx_peer_connection_t     peer;
    ngx_buf_t                *request;
    ngx_buf_t                *response;
    ngx_msec_t                connect_timeout;
    ngx_msec_t                send_timeout;
    ngx_msec_t                read_timeout;
    ngx_int_t                 rc;
    ngx_uint_t                not_event;
    ngx_http_request_t       *r;
} ngx_lua_socket_ctx_t;


static int ngx_lua_socket_open(lua_State *l);
static int ngx_lua_socket_close(lua_State *l);
static int ngx_lua_socket_send(lua_State *l);
static int ngx_lua_socket_recv(lua_State *l);
static int ngx_lua_socket_gc(lua_State *l);

static ngx_inline ngx_lua_socket_ctx_t *ngx_lua_socket(lua_State *l);

static void ngx_lua_socket_connect_handler(ngx_event_t *wev);
static void ngx_lua_socket_write_handler(ngx_event_t *wev);
static void ngx_lua_socket_read_handler(ngx_event_t *rev);
static void ngx_lua_socket_dummy_handler(ngx_event_t *ev);


static luaL_Reg  ngx_lua_socket_methods[] = {
    { "close", ngx_lua_socket_close },
    { "send", ngx_lua_socket_send },
    { "recv", ngx_lua_socket_recv },
    { "__gc", ngx_lua_socket_gc },
    { NULL, NULL }
};


void
ngx_lua_socket_api_init(lua_State *l)
{
    int  n;

    luaL_newmetatable(l, NGX_LUA_SOCKET);
    lua_pushvalue(l, -1);
    lua_setfield(l, -2, "__index");

    for (n = 0; ngx_lua_socket_methods[n].name != NULL; n++) {
        lua_pushcfunction(l, ngx_lua_socket_methods[n].func);
        lua_setfield(l, -2, ngx_lua_socket_methods[n].name);
    }

    lua_pop(l, 1);

    lua_createtable(l, 0, 1);
    lua_pushcfunction(l, ngx_lua_socket_open);
    lua_setfield(l, -2, "open");
    lua_setfield(l, -2, "socket");
}


static int
ngx_lua_socket_open(lua_State *l)
{
    char                    *errstr;
    ngx_int_t                rc;
    ngx_url_t                u;
    ngx_pool_t              *pool;
    ngx_http_request_t      *r;
    ngx_lua_socket_ctx_t   **ctx;
    ngx_peer_connection_t   *peer;

    r = ngx_lua_request(l);

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url.data = (u_char *) luaL_checklstring(l, 1, &u.url.len);
    u.default_port = 80;
    u.one_addr = 1;

    ctx = lua_newuserdata(l, sizeof(ngx_lua_socket_ctx_t *));
    luaL_getmetatable(l, NGX_LUA_SOCKET);
    lua_setmetatable(l, -2);

    *ctx = NULL;

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
        errstr = "ngx_create_pool() failed";
        goto failed;
    }

    *ctx = ngx_pcalloc(pool, sizeof(ngx_lua_socket_ctx_t));
    if (*ctx == NULL) {
        ngx_destroy_pool(pool);
        errstr = "ngx_pcalloc() failed";
        goto failed;
    }

    /* TODO: connect_timeout, send_timeout and read_timeout */

    (*ctx)->pool = pool;
    (*ctx)->connect_timeout = 60000;
    (*ctx)->send_timeout = 60000;
    (*ctx)->read_timeout = 60000;
    (*ctx)->r = r;

    if (ngx_parse_url(pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "%s in url \"%V\"", u.err, &u.url);
        }

        errstr = "ngx_parse_url() failed";

        goto failed;
    }

    peer = &(*ctx)->peer;

    peer->sockaddr = u.addrs->sockaddr;
    peer->socklen = u.addrs->socklen;
    peer->name = &u.addrs->name;
    peer->get = ngx_event_get_peer;
    peer->log = r->connection->log;
    peer->log_error = NGX_ERROR_ERR;
#if (NGX_THREADS)
    peer->lock = &r->connection->lock;
#endif

    rc = ngx_event_connect_peer(peer);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->connection->log, 0,
                   "lua socket connecting to server: %i", rc);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        errstr = "ngx_event_connect_peer() failed";
        goto failed;
    }

    peer->connection->data = *ctx;
    peer->connection->pool = pool;

    peer->connection->read->handler = ngx_lua_socket_dummy_handler;
    peer->connection->write->handler = ngx_lua_socket_connect_handler;

    if (rc == NGX_OK) {
        peer->connection->write->handler = ngx_lua_socket_dummy_handler;
        return 1;
    }

    /* rc == NGX_AGAIN */

    ngx_add_timer(peer->connection->write, (*ctx)->connect_timeout);

    return lua_yield(l, 0);

failed:

    lua_pop(l, 1);
    lua_pushnil(l);
    lua_pushstring(l, errstr);

    return 2;
}


static int
ngx_lua_socket_close(lua_State *l)
{
    ngx_lua_socket_ctx_t  *ctx;

    ctx = ngx_lua_socket(l);

    if (ctx->peer.connection) {
        ngx_close_connection(ctx->peer.connection);
    }

    ctx->peer.connection = NULL;

    return 0;
}


static int
ngx_lua_socket_send(lua_State *l)
{
    size_t                 size;
    ngx_str_t              str;
    ngx_buf_t             *b;
    ngx_http_request_t    *r;
    ngx_lua_socket_ctx_t  *ctx;

    r = ngx_lua_request(l);

    str.data = (u_char *) luaL_checklstring(l, 2, &str.len);

    ctx = ngx_lua_socket(l);

    if (ctx->peer.connection == NULL) {
        lua_pushnumber(l, NGX_ERROR);
        lua_pushstring(l, "connection is null");
        return 2;
    }

    b = ctx->request;

    if (b == NULL || (size_t) (b->end - b->start) < str.len) {
        if (b != NULL) {
            ngx_pfree(ctx->pool, b->start);
        }

        size = ngx_max(ngx_pagesize, str.len);

        b = ngx_create_temp_buf(ctx->pool, size);
        if (b == NULL) {
            lua_pushnumber(l, NGX_ERROR);
            lua_pushstring(l, "ngx_create_temp_buf() failed");
            return 2;
        }

        ctx->request = b;
    }

    b->pos = b->start;
    b->last = ngx_cpymem(b->start, str.data, str.len);

    ctx->peer.connection->read->handler = ngx_lua_socket_dummy_handler;
    ctx->peer.connection->write->handler = ngx_lua_socket_write_handler;

    ctx->rc = 0;
    ctx->not_event = 1;

    ngx_lua_socket_write_handler(ctx->peer.connection->write);

    ctx->not_event = 0;

    if (ctx->rc != NGX_AGAIN) {
        return ctx->rc;
    }

    return lua_yield(l, 0);
}


static int
ngx_lua_socket_recv(lua_State *l)
{
    ngx_buf_t             *b;
    ngx_http_request_t    *r;
    ngx_lua_socket_ctx_t  *ctx;

    r = ngx_lua_request(l);

    ctx = ngx_lua_socket(l);

    if (ctx->peer.connection == NULL) {
        lua_pushnumber(l, NGX_ERROR);
        lua_pushstring(l, "connection is null");
        return 2;
    }

    /* TODO: the size of the recv() */

    b = ctx->response;

    if (b == NULL) {
        b = ngx_create_temp_buf(ctx->pool, ngx_pagesize);
        if (b == NULL) {
            lua_pushnumber(l, NGX_ERROR);
            lua_pushstring(l, "ngx_create_temp_buf() failed");
            return 2;
        }

        ctx->response = b;
    }

    ctx->peer.connection->read->handler = ngx_lua_socket_read_handler;
    ctx->peer.connection->write->handler = ngx_lua_socket_dummy_handler;

    ctx->rc = 0;
    ctx->not_event = 1;

    ngx_lua_socket_read_handler(ctx->peer.connection->read);

    ctx->not_event = 0;

    if (ctx->rc != NGX_AGAIN) {
        return ctx->rc;
    }

    return lua_yield(l, 0);
}


static int
ngx_lua_socket_gc(lua_State *l)
{
    ngx_lua_socket_ctx_t  *ctx;

    ctx = ngx_lua_socket(l);

    if (ctx->peer.connection) {
        ngx_close_connection(ctx->peer.connection);
    }

    ngx_destroy_pool(ctx->pool);

    return 0;
}


static ngx_inline ngx_lua_socket_ctx_t *
ngx_lua_socket(lua_State *l)
{
    ngx_lua_socket_ctx_t  **ctx;

    ctx = luaL_checkudata(l, 1, NGX_LUA_SOCKET);
    if (*ctx == NULL) {
        luaL_error(l, "ngx_lua_socket() *ctx == NULL");
    }

    return *ctx;
}


static void
ngx_lua_socket_connect_handler(ngx_event_t *wev)
{
    ngx_int_t              rc;
    ngx_lua_ctx_t         *lua_ctx;
    ngx_connection_t      *c;
    ngx_lua_socket_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0,
                   "lua socket connect handler");

    c = wev->data;
    ctx = c->data;

    lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
                      "lua socket connecting %V timed out", ctx->peer.name);
        lua_pop(lua_ctx->l, 1);
        lua_pushnil(lua_ctx->l);
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    wev->handler = ngx_lua_socket_dummy_handler;

    rc = ngx_lua_thread_run(ctx->r, lua_ctx, 1);
    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_lua_finalize(ctx->r, rc);
}


static void
ngx_lua_socket_write_handler(ngx_event_t *wev)
{
    ssize_t                n, size;
    ngx_int_t              rc;
    ngx_buf_t             *b;
    ngx_lua_ctx_t         *lua_ctx;
    ngx_connection_t      *c;
    ngx_lua_socket_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "lua socket write handler");

    c = wev->data;
    ctx = c->data;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
                      "lua socket write %V timed out", ctx->peer.name);
        n = NGX_ERROR;
        goto done;
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

            if (n == size) {
                break;
            }

            /* n < size */

            continue;
        }

        if (n == NGX_AGAIN) {
            ngx_add_timer(wev, ctx->send_timeout);
            ctx->rc = NGX_AGAIN;
            return;
        }

        /* n == NGX_ERROR || n == 0 */

        break;
    }

done:

    lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

    lua_pushnumber(lua_ctx->l, n);

    ctx->rc = 1;

    if (ctx->not_event) {
        return;
    }

    rc = ngx_lua_thread_run(ctx->r, lua_ctx, ctx->rc);
    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_lua_finalize(ctx->r, rc);
}


static void
ngx_lua_socket_read_handler(ngx_event_t *rev)
{
    ssize_t                n, size;
    ngx_int_t              rc;
    ngx_buf_t             *b;
    ngx_lua_ctx_t         *lua_ctx;
    ngx_connection_t      *c;
    ngx_lua_socket_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "lua socket read handler");

    c = rev->data;
    ctx = c->data;
    b = ctx->response;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, rev->log, NGX_ETIMEDOUT,
                      "lua socket read %V timed out", ctx->peer.name);
        n = NGX_ERROR;
        goto done;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    while (1) {

        size = b->end - b->last;

        n = ngx_recv(c, b->last, size);

        if (n > 0) {
            b->last += n;
            break;
        }

        if (n == NGX_AGAIN) {
            ngx_add_timer(rev, ctx->read_timeout);
            ctx->rc = NGX_AGAIN;
            return;
        }

        /* n == NGX_ERROR || n == 0 */

        break;
    }

done:

    lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

    lua_pushnumber(lua_ctx->l, n);

    ctx->rc = 1;

    if (n > 0) {
        lua_pushlstring(lua_ctx->l, (char *) b->pos, b->last - b->pos);

        b->last = b->pos;

        ctx->rc++;
    }

    if (ctx->not_event) {
        return;
    }

    rc = ngx_lua_thread_run(ctx->r, lua_ctx, ctx->rc);
    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_lua_finalize(ctx->r, rc);
}


static void
ngx_lua_socket_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "lua socket dummy handler");
}
