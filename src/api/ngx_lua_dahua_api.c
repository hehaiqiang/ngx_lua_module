
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_module.h>


#define NGX_LUA_DAHUA_HEADER_LEN  32


#define NGX_LUA_DAHUA_CMD_LOGIN                  0xA0
#define NGX_LUA_DAHUA_CMD_LOGIN_RESPONSE         0xB0
#define NGX_LUA_DAHUA_CMD_PTZ_CONTROL            0x12
#define NGX_LUA_DAHUA_CMD_PTZ_CONTROL_RESPONSE   0x12
#define NGX_LUA_DAHUA_CMD_REQUEST_VIDEO          0x11
#define NGX_LUA_DAHUA_CMD_VIDEO_DATA_RESPONSE    0xBC
#define NGX_LUA_DAHUA_CMD_MONITOR_PIC            0x0A
#define NGX_LUA_DAHUA_CMD_PROTOCOL_RESPONSE      0xE4
#define NGX_LUA_DAHUA_CMD_REGIST_SUB_CONN        0xF1
#define NGX_LUA_DAHUA_CMD_HEART_BEAT             0xA1
#define NGX_LUA_DAHUA_CMD_HEART_BEAT_RESPONSE    0xB1
#define NGX_LUA_DAHUA_CMD_GET_CHN_NAME           0xA8
#define NGX_LUA_DAHUA_CMD_GET_CHN_NAME_RESPONSE  0xB8


#if 0
#define NGX_LUA_DAHUA_PTZ_STOP
#endif
#define NGX_LUA_DAHUA_PTZ_UP                   0x00
#define NGX_LUA_DAHUA_PTZ_DOWN                 0x01
#define NGX_LUA_DAHUA_PTZ_LEFT                 0x02
#define NGX_LUA_DAHUA_PTZ_RIGHT                0x03
#define NGX_LUA_DAHUA_PTZ_LENS_ZOOM_IN         0x04
#define NGX_LUA_DAHUA_PTZ_LENS_ZOOM_OUT        0x05
#define NGX_LUA_DAHUA_PTZ_LENS_FOCAL_FAR       0x07
#define NGX_LUA_DAHUA_PTZ_LENS_FOCAL_NEAT      0x08
#define NGX_LUA_DAHUA_PTZ_LENS_APERTURE_OPEN   0x09
#define NGX_LUA_DAHUA_PTZ_LENS_APERTURE_CLOSE  0x0A
#define NGX_LUA_DAHUA_PTZ_UP_LEFT              0x20
#define NGX_LUA_DAHUA_PTZ_UP_RIGHT             0x21
#define NGX_LUA_DAHUA_PTZ_DOWN_LEFT            0x22
#define NGX_LUA_DAHUA_PTZ_DOWN_RIGHT           0x23
#if 0
#define NGX_LUA_DAHUA_PTZ_AUTO
#define NGX_LUA_DAHUA_PTZ_PREFAB_BIT_SET
#define NGX_LUA_DAHUA_PTZ_PREFAB_BIT_DEL
#define NGX_LUA_DAHUA_PTZ_PREFAB_BIT_RUN
#define NGX_LUA_DAHUA_PTZ_MODE_SET_START
#define NGX_LUA_DAHUA_PTZ_MODE_SET_STOP
#define NGX_LUA_DAHUA_PTZ_MODE_RUN
#define NGX_LUA_DAHUA_PTZ_MENU_OPEN
#define NGX_LUA_DAHUA_PTZ_MENU_EXIT
#define NGX_LUA_DAHUA_PTZ_MENU_ENTER
#define NGX_LUA_DAHUA_PTZ_FLIP
#define NGX_LUA_DAHUA_PTZ_START
#define NGX_LUA_DAHUA_PTZ_AUX_OPEN
#define NGX_LUA_DAHUA_PTZ_AUX_STOP
#endif


#define NGX_LUA_DAHUA  "ngx_lua_dahua_ctx_t*"


typedef struct ngx_lua_dahua_cleanup_ctx_s  ngx_lua_dahua_cleanup_ctx_t;


typedef struct {
    ngx_url_t                       u;
    ngx_msec_t                      connect_timeout;
    ngx_msec_t                      send_timeout;
    ngx_msec_t                      read_timeout;
    ngx_pool_t                     *pool;
    ngx_peer_connection_t           peer;
    ngx_buf_t                      *request;
    ngx_buf_t                      *response;
    ngx_int_t                       rc;
    ngx_uint_t                      not_event;
    ngx_http_request_t             *r;
    ngx_lua_dahua_cleanup_ctx_t    *cln_ctx;

    /* DAHUA */

    ngx_uint_t                      state;

    ngx_uint_t                      command;
    size_t                          package_len;
    ngx_uint_t                      result;
    ngx_uint_t                      error;
    ngx_uint_t                      channel_n;

    u_char                         *command_start;
    u_char                         *package_len_start;
} ngx_lua_dahua_ctx_t;


struct ngx_lua_dahua_cleanup_ctx_s {
    ngx_lua_dahua_ctx_t            *ctx;
};


static int ngx_lua_dahua_open(lua_State *l);
static int ngx_lua_dahua_close(lua_State *l);
static int ngx_lua_dahua_login(lua_State *l);
static int ngx_lua_dahua_ptz(lua_State *l);
static int ngx_lua_dahua_gc(lua_State *l);

static ngx_inline ngx_lua_dahua_ctx_t *ngx_lua_dahua(lua_State *l);

static void ngx_lua_dahua_connect_handler(ngx_event_t *wev);
static void ngx_lua_dahua_write_handler(ngx_event_t *wev);
static void ngx_lua_dahua_read_handler(ngx_event_t *rev);
static void ngx_lua_dahua_dummy_handler(ngx_event_t *ev);

static void ngx_lua_dahua_cleanup(void *data);

static ngx_int_t ngx_lua_dahua_parse_login_response(ngx_lua_dahua_ctx_t *ctx);


static ngx_lua_const_t  ngx_lua_dahua_consts[] = {
    { "PTZ_UP", NGX_LUA_DAHUA_PTZ_UP },
    { "PTZ_DOWN", NGX_LUA_DAHUA_PTZ_DOWN },
    { "PTZ_LEFT", NGX_LUA_DAHUA_PTZ_LEFT },
    { "PTZ_RIGHT", NGX_LUA_DAHUA_PTZ_RIGHT },
    { "PTZ_LENS_ZOOM_IN", NGX_LUA_DAHUA_PTZ_LENS_ZOOM_IN },
    { "PTZ_LENS_ZOOM_OUT", NGX_LUA_DAHUA_PTZ_LENS_ZOOM_OUT },
    { "PTZ_LENS_FOCAL_FAR", NGX_LUA_DAHUA_PTZ_LENS_FOCAL_FAR },
    { "PTZ_LENS_FOCAL_NEAT", NGX_LUA_DAHUA_PTZ_LENS_FOCAL_NEAT },
    { "PTZ_LENS_APERTURE_OPEN", NGX_LUA_DAHUA_PTZ_LENS_APERTURE_OPEN },
    { "PTZ_LENS_APERTURE_CLOSE", NGX_LUA_DAHUA_PTZ_LENS_APERTURE_CLOSE },
    { "PTZ_UP_LEFT", NGX_LUA_DAHUA_PTZ_UP_LEFT },
    { "PTZ_UP_RIGHT", NGX_LUA_DAHUA_PTZ_UP_RIGHT },
    { "PTZ_DOWN_LEFT", NGX_LUA_DAHUA_PTZ_DOWN_LEFT },
    { "PTZ_DOWN_RIGHT", NGX_LUA_DAHUA_PTZ_DOWN_RIGHT },
    { NULL, 0 }
};


static luaL_Reg  ngx_lua_dahua_methods[] = {
    { "close", ngx_lua_dahua_close },
    { "login", ngx_lua_dahua_login },
    { "ptz", ngx_lua_dahua_ptz },
    { "__gc", ngx_lua_dahua_gc },
    { NULL, NULL }
};


void
ngx_lua_dahua_api_init(lua_State *l)
{
    int  n;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "lua dahua api init");

    luaL_newmetatable(l, NGX_LUA_DAHUA);
    lua_pushvalue(l, -1);
    lua_setfield(l, -2, "__index");

    for (n = 0; ngx_lua_dahua_methods[n].name != NULL; n++) {
        lua_pushcfunction(l, ngx_lua_dahua_methods[n].func);
        lua_setfield(l, -2, ngx_lua_dahua_methods[n].name);
    }

    lua_pop(l, 1);

    n = sizeof(ngx_lua_dahua_consts) / sizeof(ngx_lua_const_t) - 1;
    n += 1;

    lua_createtable(l, 0, n);

    for (n = 0; ngx_lua_dahua_consts[n].name != NULL; n++) {
        lua_pushinteger(l, ngx_lua_dahua_consts[n].value);
        lua_setfield(l, -2, ngx_lua_dahua_consts[n].name);
    }

    lua_pushcfunction(l, ngx_lua_dahua_open);
    lua_setfield(l, -2, "open");

    lua_setfield(l, -2, "dahua");
}


static int
ngx_lua_dahua_open(lua_State *l)
{
    char                          *errstr;
    ngx_int_t                      rc;
    ngx_str_t                      host;
    ngx_url_t                     *u;
    ngx_msec_t                     connect_timeout, send_timeout, read_timeout;
    ngx_pool_t                    *pool;
    ngx_http_cleanup_t            *cln;
    ngx_http_request_t            *r;
    ngx_lua_dahua_ctx_t          **ctx;
    ngx_peer_connection_t         *peer;
    ngx_lua_dahua_cleanup_ctx_t   *cln_ctx;

    r = ngx_lua_request(l);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lua dahua open");

    host.data = (u_char *) luaL_checklstring(l, 1, &host.len);
    connect_timeout = (ngx_msec_t) luaL_optnumber(l, 2, 60000);
    send_timeout = (ngx_msec_t) luaL_optnumber(l, 3, 60000);
    read_timeout = (ngx_msec_t) luaL_optnumber(l, 4, 60000);

    ctx = lua_newuserdata(l, sizeof(ngx_lua_dahua_ctx_t *));
    luaL_getmetatable(l, NGX_LUA_DAHUA);
    lua_setmetatable(l, -2);

    *ctx = NULL;

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
        errstr = "ngx_create_pool() failed";
        goto error;
    }

    *ctx = ngx_pcalloc(pool, sizeof(ngx_lua_dahua_ctx_t));
    if (*ctx == NULL) {
        ngx_destroy_pool(pool);
        errstr = "ngx_pcalloc() failed";
        goto error;
    }

    (*ctx)->pool = pool;

    cln_ctx = ngx_pcalloc(r->pool, sizeof(ngx_lua_dahua_cleanup_ctx_t));
    if (cln_ctx == NULL) {
        errstr = "ngx_pcalloc() failed";
        goto error;
    }

    cln_ctx->ctx = (*ctx);

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        errstr = "ngx_http_cleanup_add() failed";
        goto error;
    }

    cln->handler = ngx_lua_dahua_cleanup;
    cln->data = cln_ctx;

    (*ctx)->r = r;
    (*ctx)->cln_ctx = cln_ctx;

    (*ctx)->connect_timeout = connect_timeout;
    (*ctx)->send_timeout = send_timeout;
    (*ctx)->read_timeout = read_timeout;

    u = &(*ctx)->u;

    u->url.len = host.len;
    u->url.data = host.data;
    u->default_port = 37777;
    u->one_addr = 1;

    if (ngx_parse_url(pool, u) != NGX_OK) {
        if (u->err) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "%s in url \"%V\"", u->err, u->url);
        }

        errstr = u->err;
        goto error;
    }

    peer = &(*ctx)->peer;

    peer->sockaddr = u->addrs->sockaddr;
    peer->socklen = u->addrs->socklen;
    peer->name = &u->addrs->name;
    peer->get = ngx_event_get_peer;
    peer->log = ngx_cycle->log;
    peer->log_error = NGX_ERROR_ERR;
#if (NGX_THREADS)
    peer->lock = &r->connection->lock;
#endif

    rc = ngx_event_connect_peer(peer);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->connection->log, 0,
                   "lua dahua connecting to server: %i", rc);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        errstr = "ngx_event_connect_peer() failed";
        goto error;
    }

    peer->connection->data = *ctx;
    peer->connection->pool = pool;

    peer->connection->read->handler = ngx_lua_dahua_dummy_handler;

    if (rc == NGX_OK) {
        peer->connection->write->handler = ngx_lua_dahua_dummy_handler;
        return 1;
    }

    /* rc == NGX_AGAIN */

    peer->connection->write->handler = ngx_lua_dahua_connect_handler;

    ngx_add_timer(peer->connection->write, (*ctx)->connect_timeout);

    return lua_yield(l, 0);

error:

    lua_pop(l, 1);
    lua_pushboolean(l, 0);
    lua_pushstring(l, errstr);

    return 2;
}


static int
ngx_lua_dahua_close(lua_State *l)
{
    ngx_http_request_t   *r;
    ngx_lua_dahua_ctx_t  *ctx;

    r = ngx_lua_request(l);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua dahua close");

    ctx = ngx_lua_dahua(l);

    if (ctx->peer.connection) {
        ngx_close_connection(ctx->peer.connection);

        ctx->peer.connection = NULL;
    }

    return 0;
}


static int
ngx_lua_dahua_login(lua_State *l)
{
    char                 *errstr;
    u_char               *p;
    ngx_str_t             user, passwd;
    ngx_http_request_t   *r;
    ngx_lua_dahua_ctx_t  *ctx;

    r = ngx_lua_request(l);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua dahua login");

    user.data = (u_char *) luaL_checklstring(l, 2, &user.len);
    passwd.data = (u_char *) luaL_checklstring(l, 3, &passwd.len);

    /* TODO: user and passwd */

    ctx = ngx_lua_dahua(l);

    if (ctx->peer.connection == NULL) {
        errstr = "connection is null";
        goto error;
    }

    ctx->request->pos = ctx->request->start;

    p = ctx->request->pos;

    ngx_memzero(p, NGX_LUA_DAHUA_HEADER_LEN);

    *p++ = NGX_LUA_DAHUA_CMD_LOGIN;

    p += 7;

    ngx_memcpy(p, user.data, user.len);
    p += 8;
    ngx_memcpy(p, passwd.data, passwd.len);

    ctx->request->last = ctx->request->pos + NGX_LUA_DAHUA_HEADER_LEN;

    ctx->command = NGX_LUA_DAHUA_CMD_LOGIN_RESPONSE;

    ctx->rc = 0;
    ctx->not_event = 1;

    ngx_lua_dahua_write_handler(ctx->peer.connection->write);

    ctx->not_event = 0;

    if (ctx->rc != NGX_AGAIN) {
        lua_pushboolean(l, 1);
        return 1;
    }

    ctx->peer.connection->write->handler = ngx_lua_dahua_write_handler;

    return lua_yield(l, 0);

error:

    lua_pushboolean(l, 0);
    lua_pushstring(l, errstr);

    return 2;
}


static int
ngx_lua_dahua_ptz(lua_State *l)
{
    int                   code, param1, param2, channel;
    char                 *errstr;
    u_char               *p;
    ngx_http_request_t   *r;
    ngx_lua_dahua_ctx_t  *ctx;

    r = ngx_lua_request(l);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lua dahua ptz");

    code = luaL_checkint(l, 2);
    param1 = luaL_checkint(l, 3);
    param2 = luaL_checkint(l, 4);
    channel = luaL_checkint(l, 5);

    /* TODO: code, param1, param2, channel */

    ctx = ngx_lua_dahua(l);

    if (ctx->peer.connection == NULL) {
        errstr = "connection is null";
        goto error;
    }

    ctx->request->pos = ctx->request->start;

    p = ctx->request->pos;

    ngx_memzero(p, NGX_LUA_DAHUA_HEADER_LEN);

    *p++ = NGX_LUA_DAHUA_CMD_PTZ_CONTROL;

    p += 8;

    *p++ = (u_char) channel;

    /* TODO: command */

    *p++ = (u_char) code;
    *p++ = 0x0A;
    *p++ = 5;

    ctx->request->last = ctx->request->pos + NGX_LUA_DAHUA_HEADER_LEN;

    ctx->command = NGX_LUA_DAHUA_CMD_PTZ_CONTROL_RESPONSE;

    ctx->rc = 0;
    ctx->not_event = 1;

    ngx_lua_dahua_write_handler(ctx->peer.connection->write);

    ctx->not_event = 0;

    if (ctx->rc != NGX_AGAIN) {
        lua_pushboolean(l, 1);
        return 1;
    }

    ctx->peer.connection->write->handler = ngx_lua_dahua_write_handler;

    return lua_yield(l, 0);

error:

    lua_pushboolean(l, 0);
    lua_pushstring(l, errstr);

    return 2;
}


static int
ngx_lua_dahua_gc(lua_State *l)
{
    ngx_lua_dahua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "lua dahua gc");

    ctx = ngx_lua_dahua(l);

    if (ctx->cln_ctx != NULL) {
        ctx->cln_ctx->ctx = NULL;
    }

    if (ctx->peer.connection) {
        ngx_close_connection(ctx->peer.connection);

        ctx->peer.connection = NULL;
    }

    ngx_destroy_pool(ctx->pool);

    return 0;
}


static ngx_inline ngx_lua_dahua_ctx_t *
ngx_lua_dahua(lua_State *l)
{
    ngx_lua_dahua_ctx_t  **ctx;

    ctx = luaL_checkudata(l, 1, NGX_LUA_DAHUA);
    if (*ctx == NULL) {
        luaL_error(l, "ngx_lua_dahua() (*ctx) == NULL");
    }

    return *ctx;
}


static void
ngx_lua_dahua_connect_handler(ngx_event_t *wev)
{
    ngx_int_t             rc;
    ngx_lua_ctx_t        *lua_ctx;
    ngx_connection_t     *c;
    ngx_lua_dahua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0,
                   "lua dahua connect handler");

    c = wev->data;
    ctx = c->data;

    if (ctx->r == NULL) {
        return;
    }

    lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

    ctx->rc = 1;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
                      "lua dahua connecting %V timed out", ctx->peer.name);

        lua_pop(lua_ctx->l, 1);
        lua_pushboolean(lua_ctx->l, 0);
        lua_pushstring(lua_ctx->l, "ngx_lua_dahua_connect_handler() timed out");

        ctx->rc++;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    wev->handler = ngx_lua_dahua_dummy_handler;

    ctx->request = ngx_create_temp_buf(ctx->pool, ngx_pagesize);
    if (ctx->request == NULL) {
        lua_pop(lua_ctx->l, 1);
        lua_pushboolean(lua_ctx->l, 0);
        lua_pushstring(lua_ctx->l, "ngx_create_temp_buf() failed");

        ctx->rc++;
    }

    rc = ngx_lua_thread_run(ctx->r, lua_ctx, ctx->rc);
    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_lua_finalize(ctx->r, rc);
}


static void
ngx_lua_dahua_write_handler(ngx_event_t *wev)
{
    char                 *errstr;
    ssize_t               n, size;
    ngx_int_t             rc;
    ngx_buf_t            *b;
    ngx_lua_ctx_t        *lua_ctx;
    ngx_connection_t     *c;
    ngx_lua_dahua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "lua dahua write handler");

    c = wev->data;
    ctx = c->data;
    b = ctx->request;
    errstr = NULL;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
                      "lua dahua write %V timed out", ctx->peer.name);
        errstr = "ngx_lua_dahua_write_handler() timed out";
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

            if (n < size) {
                continue;
            }

            /* n == size */

            if (ctx->command == NGX_LUA_DAHUA_CMD_LOGIN_RESPONSE) {
                wev->handler = ngx_lua_dahua_dummy_handler;

                ctx->rc = 0;

                ngx_lua_dahua_read_handler(c->read);

                if (ctx->rc == NGX_AGAIN) {
                    c->read->handler = ngx_lua_dahua_read_handler;
                    return;
                }

            } else if (ctx->command == NGX_LUA_DAHUA_CMD_PTZ_CONTROL_RESPONSE) {
                /* TODO */
            }

            break;
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

    wev->handler = ngx_lua_dahua_dummy_handler;

    if (ctx->r == NULL) {
        return;
    }

    lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

    ctx->rc = 1;

    if (n > 0) {
        lua_pushboolean(lua_ctx->l, 1);

    } else {
        lua_pushboolean(lua_ctx->l, 0);

        if (errstr != NULL) {
            lua_pushstring(lua_ctx->l, errstr);

            ctx->rc++;
        }
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
ngx_lua_dahua_read_handler(ngx_event_t *rev)
{
    char                 *errstr;
    ssize_t               n;
    ngx_int_t             rc;
    ngx_buf_t            *b;
    ngx_lua_ctx_t        *lua_ctx;
    ngx_connection_t     *c;
    ngx_lua_dahua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "lua dahua read handler");

    c = rev->data;
    ctx = c->data;
    errstr = NULL;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, rev->log, NGX_ETIMEDOUT,
                      "lua dahua read %V timed out", ctx->peer.name);
        errstr = "ngx_lua_dahua_read_handler() timed out";
        n = NGX_ERROR;
        goto done;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    b = ctx->response;

    if (b == NULL) {
        b = ngx_create_temp_buf(ctx->pool, ngx_pagesize);
        if (b == NULL) {
            errstr = "ngx_create_temp_buf() failed";
            n = NGX_ERROR;
            goto done;
        }

        ctx->response = b;
    }

    while (1) {

        n = ngx_recv(c, b->last, b->end - b->last);

        if (n > 0) {
            b->last += n;

            /* TODO: parsing response */

            rc = ngx_lua_dahua_parse_login_response(ctx);

            if (rc == NGX_AGAIN) {
                ctx->rc = NGX_AGAIN;
                return;
            }

            if (rc == NGX_ERROR) {
                n = NGX_ERROR;
            }

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

    rev->handler = ngx_lua_dahua_dummy_handler;

    if (ctx->r == NULL) {
        return;
    }

    lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

    ctx->rc = 1;

    if (n > 0) {
        lua_pushboolean(lua_ctx->l, 1);

    } else {
        lua_pushboolean(lua_ctx->l, 0);

        if (errstr != NULL) {
            lua_pushstring(lua_ctx->l, errstr);

            ctx->rc++;
        }
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
ngx_lua_dahua_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "lua dahua dummy handler");
}


static void
ngx_lua_dahua_cleanup(void *data)
{
    ngx_lua_dahua_cleanup_ctx_t *cln_ctx = data;

    if (cln_ctx->ctx != NULL) {
        cln_ctx->ctx->r = NULL;
        cln_ctx->ctx->cln_ctx = NULL;
    }
}


static ngx_int_t
ngx_lua_dahua_parse_login_response(ngx_lua_dahua_ctx_t *ctx)
{
    u_char  *p, ch;
    enum {
        sw_start = 0,
        sw_package_len_before,
        sw_package_len,
        sw_result,
        sw_error,
        sw_channels,
        sw_video_codec,
        sw_device_type,
        sw_unused,
        sw_almost_done
    } state;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "lua dahua parse login response");

    state = ctx->state;

    for (p = ctx->response->pos; p < ctx->response->last; p++) {
        ch = *p;

        switch (state) {

        case sw_start:
            if (ch != NGX_LUA_DAHUA_CMD_LOGIN_RESPONSE) {
                return NGX_ERROR;
            }

            ctx->command_start = p;

            state = sw_package_len_before;
            break;

        case sw_package_len_before:
            if (p - ctx->command_start < 4) {
                break;
            }

            ctx->package_len_start = p;

            state = sw_package_len;
            break;

        case sw_package_len:
            if (p - ctx->package_len_start < 3) {
                break;
            }

            ctx->package_len = *((size_t *) ctx->package_len_start);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                           "package_len:%uz", ctx->package_len);

            state = sw_result;
            break;

        case sw_result:
            ctx->result = (ngx_uint_t) ch;

            /* TODO: error handling */

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                           "result:%ui", ctx->result);

            state = sw_error;
            break;

        case sw_error:
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                           "error:%ui", (ngx_uint_t) ch);

            state = sw_channels;
            break;

        case sw_channels:
            ctx->channel_n = (ngx_uint_t) ch;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                           "channel_n:%ui", ch);

            state = sw_video_codec;
            break;

        case sw_video_codec:
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                           "video_codec:%ui", (ngx_uint_t) ch);

            state = sw_device_type;
            break;

        case sw_device_type:
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                           "device_type:%ui", (ngx_uint_t) ch);

            state = sw_unused;
            break;

        case sw_unused:
            if (p - ctx->command_start < NGX_LUA_DAHUA_HEADER_LEN - 2) {
                break;
            }

            state = sw_almost_done;
            break;

        case sw_almost_done:
            goto done;
        }
    }

    ctx->response->pos = p;
    ctx->state = state;

    return NGX_AGAIN;

done:

    ctx->response->pos = p + 1;
    ctx->state = 0;

    /* TODO: p == ctx->response->last */

    ctx->response->pos = ctx->response->start;
    ctx->response->last = ctx->response->start;

    return NGX_OK;
}
