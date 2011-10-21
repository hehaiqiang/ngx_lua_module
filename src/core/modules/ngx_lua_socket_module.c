
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua.h>


#define NGX_LUA_SOCKET  "ngx_lua_socket_ctx_t*"


#define NGX_LUA_SOCKET_TCP  1
#define NGX_LUA_SOCKET_UDP  2


typedef struct ngx_lua_socket_cleanup_ctx_s  ngx_lua_socket_cleanup_ctx_t;


typedef struct {
    ngx_pool_t                      *pool;
    ngx_peer_connection_t            peer;
    ngx_udp_connection_t             udp_connection;
    ngx_uint_t                       type;
    ngx_msec_t                       connect_timeout;
    ngx_msec_t                       send_timeout;
    ngx_msec_t                       read_timeout;
    ngx_buf_t                       *request;
    ngx_buf_t                       *response;
    ngx_int_t                        rc;
    ngx_uint_t                       not_event;
    ngx_lua_thread_t                *thr;
    ngx_lua_socket_cleanup_ctx_t    *cln_ctx;
} ngx_lua_socket_ctx_t;


struct ngx_lua_socket_cleanup_ctx_s {
    ngx_lua_socket_ctx_t            *ctx;
};


extern ngx_int_t ngx_udp_connect(ngx_udp_connection_t *uc);


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

static void ngx_lua_socket_cleanup(void *data);

static int ngx_lua_socket_udp_open(lua_State *l, ngx_lua_thread_t *thr,
    ngx_lua_socket_ctx_t *ctx, ngx_url_t *u);
static int ngx_lua_socket_udp_send(lua_State *l, ngx_lua_thread_t *thr,
    ngx_lua_socket_ctx_t *ctx, ngx_str_t *str);
static int ngx_lua_socket_udp_recv(lua_State *l, ngx_lua_thread_t *thr,
    ngx_lua_socket_ctx_t *ctx);
static void ngx_lua_socket_udp_read_handler(ngx_event_t *rev);

static ngx_int_t ngx_lua_socket_module_init(ngx_cycle_t *cycle);


static luaL_Reg  ngx_lua_socket_methods[] = {
    { "close", ngx_lua_socket_close },
    { "send", ngx_lua_socket_send },
    { "recv", ngx_lua_socket_recv },
    { "__gc", ngx_lua_socket_gc },
    { NULL, NULL }
};


ngx_module_t  ngx_lua_socket_module = {
    NGX_MODULE_V1,
    NULL,                                  /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_lua_socket_module_init,            /* init module */
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
        &ngx_lua_socket_module,
        NULL
    };

    return modules;
}
#endif


static int
ngx_lua_socket_open(lua_State *l)
{
    char                            *errstr;
    ngx_int_t                        rc;
    ngx_url_t                        u;
    ngx_uint_t                       type;
    ngx_msec_t                       connect_timeout, send_timeout;
    ngx_msec_t                       read_timeout;
    ngx_pool_t                      *pool;
    ngx_lua_thread_t                *thr;
    ngx_pool_cleanup_t              *cln;
    ngx_lua_socket_ctx_t          **ctx;
    ngx_peer_connection_t          *peer;
    ngx_lua_socket_cleanup_ctx_t   *cln_ctx;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua socket open");

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url.data = (u_char *) luaL_checklstring(l, 1, &u.url.len);
    type = (ngx_uint_t) luaL_optnumber(l, 2, NGX_LUA_SOCKET_TCP);
    connect_timeout = (ngx_msec_t) luaL_optnumber(l, 3, 60000);
    send_timeout = (ngx_msec_t) luaL_optnumber(l, 4, 60000);
    read_timeout = (ngx_msec_t) luaL_optnumber(l, 5, 60000);

    ctx = lua_newuserdata(l, sizeof(ngx_lua_socket_ctx_t *));
    luaL_getmetatable(l, NGX_LUA_SOCKET);
    lua_setmetatable(l, -2);

    *ctx = NULL;

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
        errstr = "ngx_create_pool() failed";
        goto error;
    }

    *ctx = ngx_pcalloc(pool, sizeof(ngx_lua_socket_ctx_t));
    if (*ctx == NULL) {
        ngx_destroy_pool(pool);
        errstr = "ngx_pcalloc() failed";
        goto error;
    }

    (*ctx)->pool = pool;
    (*ctx)->type = type;
    (*ctx)->connect_timeout = connect_timeout;
    (*ctx)->send_timeout = send_timeout;
    (*ctx)->read_timeout = read_timeout;

    cln_ctx = ngx_pcalloc(thr->pool, sizeof(ngx_lua_socket_cleanup_ctx_t));
    if (cln_ctx == NULL) {
        errstr = "ngx_pcalloc() failed";
        goto error;
    }

    cln_ctx->ctx = (*ctx);

    cln = ngx_pool_cleanup_add(thr->pool, 0);
    if (cln == NULL) {
        errstr = "ngx_pool_cleanup_add() failed";
        goto error;
    }

    cln->handler = ngx_lua_socket_cleanup;
    cln->data = cln_ctx;

    (*ctx)->thr = thr;
    (*ctx)->cln_ctx = cln_ctx;

    u.default_port = 80;
    u.one_addr = 1;

    if (ngx_parse_url(pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, thr->log, 0,
                          "%s in url \"%V\"", u.err, &u.url);
        }

        errstr = u.err;
        goto error;
    }

    if (type == NGX_LUA_SOCKET_UDP) {
        return ngx_lua_socket_udp_open(l, thr, *ctx, &u);
    }

    peer = &(*ctx)->peer;

    peer->sockaddr = u.addrs->sockaddr;
    peer->socklen = u.addrs->socklen;
    peer->name = &u.addrs->name;
    peer->get = ngx_event_get_peer;
    peer->log = ngx_cycle->log;
    peer->log_error = NGX_ERROR_ERR;
#if (NGX_THREADS)
    peer->lock = &thr->c->lock;
#endif

    rc = ngx_event_connect_peer(peer);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, thr->log, 0,
                   "lua socket connecting to server: %i", rc);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        errstr = "ngx_event_connect_peer() failed";
        goto error;
    }

    peer->connection->data = *ctx;
    peer->connection->pool = pool;

    peer->connection->read->handler = ngx_lua_socket_dummy_handler;

    if (rc == NGX_OK) {
        peer->connection->write->handler = ngx_lua_socket_dummy_handler;
        return 1;
    }

    /* rc == NGX_AGAIN */

    peer->connection->write->handler = ngx_lua_socket_connect_handler;

    ngx_add_timer(peer->connection->write, (*ctx)->connect_timeout);

    return lua_yield(l, 0);

error:

    lua_pop(l, 1);
    lua_pushboolean(l, 0);
    lua_pushstring(l, errstr);

    return 2;
}


static int
ngx_lua_socket_close(lua_State *l)
{
    ngx_lua_socket_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "lua socket close");

    ctx = ngx_lua_socket(l);

    if (ctx->type == NGX_LUA_SOCKET_TCP) {
        if (ctx->peer.connection) {
            ngx_close_connection(ctx->peer.connection);
            ctx->peer.connection = NULL;
        }

    } else {

        if (ctx->udp_connection.connection) {
            ngx_close_connection(ctx->udp_connection.connection);
            ctx->udp_connection.connection = NULL;
        }
    }

    return 0;
}


static int
ngx_lua_socket_send(lua_State *l)
{
    char                  *errstr;
    size_t                 size;
    ngx_str_t              str;
    ngx_buf_t             *b;
    ngx_lua_thread_t      *thr;
    ngx_lua_socket_ctx_t  *ctx;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua socket send");

    str.data = (u_char *) luaL_checklstring(l, 2, &str.len);

    ctx = ngx_lua_socket(l);

    if (ctx->type == NGX_LUA_SOCKET_UDP) {
        return ngx_lua_socket_udp_send(l, thr, ctx, &str);
    }

    if (ctx->peer.connection == NULL) {
        errstr = "connection is null";
        goto error;
    }

    b = ctx->request;

    if (b == NULL || (size_t) (b->end - b->start) < str.len) {
        if (b != NULL && (size_t) (b->end - b->start) > ctx->pool->max) {
            ngx_pfree(ctx->pool, b->start);
        }

        size = ngx_max(ngx_pagesize, str.len);

        b = ngx_create_temp_buf(ctx->pool, size);
        if (b == NULL) {
            errstr = "ngx_create_temp_buf() failed";
            goto error;
        }

        ctx->request = b;
    }

    b->pos = b->start;
    b->last = ngx_cpymem(b->pos, str.data, str.len);

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

error:

    lua_pushboolean(l, 0);
    lua_pushstring(l, errstr);

    return 2;
}


static int
ngx_lua_socket_recv(lua_State *l)
{
    char                  *errstr;
    size_t                 size;
    ngx_buf_t             *b;
    ngx_lua_thread_t      *thr;
    ngx_lua_socket_ctx_t  *ctx;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua socket recv");

    ctx = ngx_lua_socket(l);

    size = (size_t) luaL_optnumber(l, 2, ngx_pagesize);

    b = ctx->response;

    if (b == NULL || (size_t) (b->end - b->start) < size) {
        if (b != NULL && (size_t) (b->end - b->start) > ctx->pool->max) {
            ngx_pfree(ctx->pool, b->start);
        }

        size = ngx_max(ngx_pagesize, size);

        b = ngx_create_temp_buf(ctx->pool, size);
        if (b == NULL) {
            errstr = "ngx_create_temp_buf() failed";
            goto error;
        }

        ctx->response = b;
    }

    b->last = b->pos;

    if (ctx->type == NGX_LUA_SOCKET_UDP) {
        return ngx_lua_socket_udp_recv(l, thr, ctx);
    }

    if (ctx->peer.connection == NULL) {
        errstr = "connection is null";
        goto error;
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

error:

    lua_pushboolean(l, 0);
    lua_pushstring(l, errstr);

    return 2;
}


static int
ngx_lua_socket_gc(lua_State *l)
{
    ngx_lua_socket_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "lua socket gc");

    ctx = ngx_lua_socket(l);

    if (ctx->cln_ctx != NULL) {
        ctx->cln_ctx->ctx = NULL;
    }

    ngx_lua_socket_close(l);

    ngx_destroy_pool(ctx->pool);

    return 0;
}


static ngx_inline ngx_lua_socket_ctx_t *
ngx_lua_socket(lua_State *l)
{
    ngx_lua_socket_ctx_t  **ctx;

    ctx = luaL_checkudata(l, 1, NGX_LUA_SOCKET);
    if (*ctx == NULL) {
        luaL_error(l, "ngx_lua_socket() (*ctx) == NULL");
    }

    return *ctx;
}


static void
ngx_lua_socket_connect_handler(ngx_event_t *wev)
{
    ngx_int_t              rc;
    ngx_connection_t      *c;
    ngx_lua_thread_t      *thr;
    ngx_lua_socket_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, wev->log, 0,
                   "lua socket connect handler");

    c = wev->data;
    ctx = c->data;
    thr = ctx->thr;

    ctx->rc = 1;

    if (thr == NULL) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
                      "lua socket connecting %V timed out", ctx->peer.name);

        lua_pop(thr->l, 1);
        lua_pushboolean(thr->l, 0);
        lua_pushstring(thr->l, "ngx_lua_socket_connect_handler() timed out");

        ctx->rc++;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    wev->handler = ngx_lua_socket_dummy_handler;

    rc = ngx_lua_thread_run(thr, ctx->rc);
    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_lua_finalize(thr, rc);
}


static void
ngx_lua_socket_write_handler(ngx_event_t *wev)
{
    char                  *errstr;
    ssize_t                n, size;
    ngx_int_t              rc;
    ngx_buf_t             *b;
    ngx_connection_t      *c;
    ngx_lua_thread_t      *thr;
    ngx_lua_socket_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, wev->log, 0, "lua socket write handler");

    c = wev->data;
    ctx = c->data;
    b = ctx->request;
    errstr = NULL;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
                      "lua socket write %V timed out", ctx->peer.name);
        errstr = "ngx_lua_socket_write_handler() timed out";
        n = NGX_ERROR;
        goto done;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

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

    wev->handler = ngx_lua_socket_dummy_handler;

    thr = ctx->thr;
    if (thr == NULL) {
        return;
    }

    ctx->rc = 1;

    if (n > 0) {
        lua_pushnumber(thr->l, b->last - b->start);

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
ngx_lua_socket_read_handler(ngx_event_t *rev)
{
    char                  *errstr;
    ssize_t                n;
    ngx_int_t              rc;
    ngx_buf_t             *b;
    ngx_connection_t      *c;
    ngx_lua_thread_t      *thr;
    ngx_lua_socket_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, rev->log, 0, "lua socket read handler");

    c = rev->data;
    ctx = c->data;
    b = ctx->response;
    errstr = NULL;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, rev->log, NGX_ETIMEDOUT,
                      "lua socket read %V timed out", ctx->peer.name);
        errstr = "ngx_lua_socket_read_handler() timed out";
        n = NGX_ERROR;
        goto done;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    while (1) {

        n = ngx_recv(c, b->last, b->end - b->last);

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

    rev->handler = ngx_lua_socket_dummy_handler;

    thr = ctx->thr;
    if (thr == NULL) {
        return;
    }

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
ngx_lua_socket_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "lua socket dummy handler");
}


static void
ngx_lua_socket_cleanup(void *data)
{
    ngx_lua_socket_cleanup_ctx_t *cln_ctx = data;

    if (cln_ctx->ctx != NULL) {
        cln_ctx->ctx->thr = NULL;
        cln_ctx->ctx->cln_ctx = NULL;
    }
}


static int
ngx_lua_socket_udp_open(lua_State *l, ngx_lua_thread_t *thr,
    ngx_lua_socket_ctx_t *ctx, ngx_url_t *u)
{
    ngx_int_t              rc;
    ngx_udp_connection_t  *uc;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua socket udp open");

    uc = &ctx->udp_connection;

    uc->sockaddr = u->addrs->sockaddr;
    uc->socklen = u->addrs->socklen;
    uc->server = u->addrs->name;
    uc->log = *ngx_cycle->log;

    rc = ngx_udp_connect(uc);

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, thr->log, ngx_socket_errno,
                      "ngx_udp_connect() failed");
        lua_pop(l, 1);
        lua_pushboolean(l, 0);
        lua_pushstring(l, "ngx_udp_connect() failed");
        return 2;
    }

    uc->connection->data = ctx;
    uc->connection->pool = ctx->pool;

    uc->connection->read->handler = ngx_lua_socket_dummy_handler;
    uc->connection->write->handler = ngx_lua_socket_dummy_handler;

    return 1;
}


static int
ngx_lua_socket_udp_send(lua_State *l, ngx_lua_thread_t *thr,
    ngx_lua_socket_ctx_t *ctx, ngx_str_t *str)
{
    char                  *errstr;
    ssize_t                n;
    ngx_udp_connection_t  *uc;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua socket udp send");

    uc = &ctx->udp_connection;

    if (uc->connection == NULL) {
        errstr = "udp connection is null";
        goto error;
    }

    n = sendto(uc->connection->fd, (char *) str->data, str->len, 0,
               uc->sockaddr, uc->socklen);

    /* TODO: n == 0 */

    if (n == -1) {
        ngx_connection_error(uc->connection, ngx_socket_errno,
                             "sendto() failed");
        errstr = "sendto() failed";
        goto error;
    }

    if ((size_t) n != str->len) {
        ngx_log_error(NGX_LOG_CRIT, thr->log, 0,
                      "sendto() incomplete n:%z size:%uz", n, str->len);
        errstr = "sendto() incomplete";
        goto error;
    }

    /* n > 0 */

    lua_pushnumber(l, n);

    return 1;

error:

    lua_pushboolean(l, 0);
    lua_pushstring(l, errstr);

    return 2;
}


static int
ngx_lua_socket_udp_recv(lua_State *l, ngx_lua_thread_t *thr,
    ngx_lua_socket_ctx_t *ctx)
{
    ngx_udp_connection_t  *uc;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua socket udp recv");

    uc = &ctx->udp_connection;

    if (uc->connection == NULL) {
        lua_pushboolean(l, 0);
        lua_pushstring(l, "connection is null");
        return 2;
    }

    uc->connection->read->handler = ngx_lua_socket_udp_read_handler;

    ctx->rc = 0;
    ctx->not_event = 1;

    ngx_lua_socket_udp_read_handler(uc->connection->read);

    ctx->not_event = 0;

    if (ctx->rc != NGX_AGAIN) {
        return ctx->rc;
    }

    return lua_yield(l, 0);
}


static void
ngx_lua_socket_udp_read_handler(ngx_event_t *rev)
{
    char                  *errstr;
    ssize_t                n;
    ngx_int_t              rc;
    ngx_buf_t             *b;
    ngx_connection_t      *c;
    ngx_lua_thread_t      *thr;
    ngx_lua_socket_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, rev->log, 0,
                   "lua socket udp read handler");

    c = rev->data;
    ctx = c->data;
    b = ctx->response;
    errstr = NULL;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, rev->log, NGX_ETIMEDOUT,
                      "lua socket udp read %V timed out",
                      &ctx->udp_connection.server);
        errstr = "ngx_lua_socket_udp_read_handler() timed out";
        n = NGX_ERROR;
        goto done;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    n = ngx_udp_recv(c, b->last, b->end - b->last);

    if (n == NGX_AGAIN) {
        ngx_add_timer(rev, ctx->read_timeout);

#if 0
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            n = NGX_ERROR;
            goto done;
        }
#endif

        ctx->rc = NGX_AGAIN;
        return;
    }

    /* TODO: n == NGX_ERROR, n == 0, n > 0 */

done:

    rev->handler = ngx_lua_socket_dummy_handler;

    thr = ctx->thr;
    if (thr == NULL) {
        return;
    }

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


static ngx_int_t
ngx_lua_socket_module_init(ngx_cycle_t *cycle)
{
    int              n;
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua socket module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    lua_getglobal(lcf->l, NGX_LUA_TABLE);

    luaL_newmetatable(lcf->l, NGX_LUA_SOCKET);
    lua_pushvalue(lcf->l, -1);
    lua_setfield(lcf->l, -2, "__index");

    for (n = 0; ngx_lua_socket_methods[n].name != NULL; n++) {
        lua_pushcfunction(lcf->l, ngx_lua_socket_methods[n].func);
        lua_setfield(lcf->l, -2, ngx_lua_socket_methods[n].name);
    }

    lua_pop(lcf->l, 1);

    lua_createtable(lcf->l, 0, 3);

    lua_pushinteger(lcf->l, NGX_LUA_SOCKET_TCP);
    lua_setfield(lcf->l, -2, "TCP");
    lua_pushinteger(lcf->l, NGX_LUA_SOCKET_UDP);
    lua_setfield(lcf->l, -2, "UDP");
    lua_pushcfunction(lcf->l, ngx_lua_socket_open);
    lua_setfield(lcf->l, -2, "open");

    lua_setfield(lcf->l, -2, "socket");

    lua_pop(lcf->l, 1);

    return NGX_OK;
}
