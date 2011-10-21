
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua.h>


#define NGX_LUA_DAHUA_HEADER_LEN  32


#define NGX_LUA_DAHUA_CMD_LOGIN                  0xA0
#define NGX_LUA_DAHUA_CMD_LOGIN_RESP             0xB0
#define NGX_LUA_DAHUA_CMD_PTZ                    0x12
#define NGX_LUA_DAHUA_CMD_PTZ_RESP               0xE4
#define NGX_LUA_DAHUA_CMD_VIDEO                  0x11
#define NGX_LUA_DAHUA_CMD_VIDEO_RESP             0xBC
#if 0
#define NGX_LUA_DAHUA_CMD_MONITOR_PIC            0x0A
#define NGX_LUA_DAHUA_CMD_PROTOCOL_RESP          0xE4 /* TODO */
#endif
#define NGX_LUA_DAHUA_CMD_REG_SUB_CONN           0xF1
#define NGX_LUA_DAHUA_CMD_REG_SUB_CONN_RESP      0xF1
#define NGX_LUA_DAHUA_CMD_HEART_BEAT             0xA1
#define NGX_LUA_DAHUA_CMD_HEART_BEAT_RESP        0xB1
#define NGX_LUA_DAHUA_CMD_GET_CHN_NAME           0xA8
#define NGX_LUA_DAHUA_CMD_GET_CHN_NAME_RESP      0xB8


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
    ngx_peer_connection_t           sub_peer;
    ngx_buf_t                      *request;
    ngx_buf_t                      *response;
    ngx_int_t                       rc;
    ngx_uint_t                      not_event;
    ngx_lua_thread_t               *thr;
    ngx_lua_dahua_cleanup_ctx_t    *cln_ctx;

    int                             channel;
    int                             type;

    ngx_uint_t                      state;
    u_char                         *msg_start;
    u_char                          cmd;
    u_char                         *extlen_start;
    size_t                          extlen;
    u_char                          result;
    u_char                          error;
    u_char                          channel_n;
    u_char                          vcodec;
    u_char                          dev_type;
    u_char                         *id_start;
    u_char                          id[4];
} ngx_lua_dahua_ctx_t;


struct ngx_lua_dahua_cleanup_ctx_s {
    ngx_lua_dahua_ctx_t            *ctx;
};


static int ngx_lua_dahua_open(lua_State *l);
static int ngx_lua_dahua_close(lua_State *l);
static int ngx_lua_dahua_login(lua_State *l);
static int ngx_lua_dahua_ptz(lua_State *l);
static int ngx_lua_dahua_snapshot(lua_State *l);
static int ngx_lua_dahua_video(lua_State *l);
static int ngx_lua_dahua_audio(lua_State *l);
static int ngx_lua_dahua_gc(lua_State *l);

static ngx_inline ngx_lua_dahua_ctx_t *ngx_lua_dahua(lua_State *l);

static void ngx_lua_dahua_connect_handler(ngx_event_t *wev);
static void ngx_lua_dahua_write_handler(ngx_event_t *wev);
static void ngx_lua_dahua_read_handler(ngx_event_t *rev);
static void ngx_lua_dahua_dummy_handler(ngx_event_t *ev);

static void ngx_lua_dahua_cleanup(void *data);

static ngx_int_t ngx_lua_dahua_parse_login_response(ngx_lua_dahua_ctx_t *ctx);
static ngx_int_t ngx_lua_dahua_parse_heart_beat_response(
    ngx_lua_dahua_ctx_t *ctx);
static ngx_int_t ngx_lua_dahua_parse_reg_sub_conn_response(
    ngx_lua_dahua_ctx_t *ctx);
static ngx_int_t ngx_lua_dahua_parse_video_response(ngx_lua_dahua_ctx_t *ctx);

static void ngx_lua_dahua_sub_connect_handler(ngx_event_t *wev);

static ngx_int_t ngx_lua_dahua_module_init(ngx_cycle_t *cycle);


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
    { "snapshot", ngx_lua_dahua_snapshot },
    { "video", ngx_lua_dahua_video },
    { "audio", ngx_lua_dahua_audio },
    { "__gc", ngx_lua_dahua_gc },
    { NULL, NULL }
};


ngx_module_t  ngx_lua_dahua_module = {
    NGX_MODULE_V1,
    NULL,                                  /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_lua_dahua_module_init,             /* init module */
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
        &ngx_lua_dahua_module,
        NULL
    };

    return modules;
}
#endif


static int
ngx_lua_dahua_open(lua_State *l)
{
    char                          *errstr;
    ngx_int_t                      rc;
    ngx_str_t                      host;
    ngx_url_t                     *u;
    ngx_msec_t                     connect_timeout, send_timeout, read_timeout;
    ngx_pool_t                    *pool;
    ngx_lua_thread_t              *thr;
    ngx_pool_cleanup_t            *cln;
    ngx_lua_dahua_ctx_t          **ctx;
    ngx_peer_connection_t         *peer;
    ngx_lua_dahua_cleanup_ctx_t   *cln_ctx;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua dahua open");

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

    cln_ctx = ngx_pcalloc(thr->pool, sizeof(ngx_lua_dahua_cleanup_ctx_t));
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

    cln->handler = ngx_lua_dahua_cleanup;
    cln->data = cln_ctx;

    (*ctx)->thr = thr;
    (*ctx)->cln_ctx = cln_ctx;

    (*ctx)->connect_timeout = connect_timeout;
    (*ctx)->send_timeout = send_timeout;
    (*ctx)->read_timeout = read_timeout;

    u = &(*ctx)->u;

    u->url.len = host.len;
    u->url.data = ngx_pstrdup(pool, &host);
    u->default_port = 37777;
    u->one_addr = 1;

    if (ngx_parse_url(pool, u) != NGX_OK) {
        if (u->err) {
            ngx_log_error(NGX_LOG_EMERG, thr->log, 0,
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
    peer->lock = &thr->c->lock;
#endif

    rc = ngx_event_connect_peer(peer);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, thr->log, 0,
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
    ngx_lua_dahua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "lua dahua close");

    ctx = ngx_lua_dahua(l);

    if (ctx->peer.connection) {
        ngx_close_connection(ctx->peer.connection);
        ctx->peer.connection = NULL;
    }

    if (ctx->sub_peer.connection) {
        ngx_close_connection(ctx->sub_peer.connection);
        ctx->sub_peer.connection = NULL;
    }

    return 0;
}


static int
ngx_lua_dahua_login(lua_State *l)
{
    char                 *errstr;
    u_char               *p;
    ngx_str_t             user, passwd;
    ngx_buf_t            *b;
    ngx_lua_thread_t     *thr;
    ngx_lua_dahua_ctx_t  *ctx;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua dahua login");

    user.data = (u_char *) luaL_checklstring(l, 2, &user.len);
    passwd.data = (u_char *) luaL_checklstring(l, 3, &passwd.len);

    /* TODO: user and passwd */

    ctx = ngx_lua_dahua(l);

    if (ctx->peer.connection == NULL) {
        errstr = "connection is null";
        goto error;
    }

    b = ctx->request;
    b->pos = b->start;

    p = b->pos;
    ngx_memzero(p, NGX_LUA_DAHUA_HEADER_LEN);

    *p++ = NGX_LUA_DAHUA_CMD_LOGIN;
    p += 7;

    ngx_memcpy(p, user.data, user.len);
    p += 8;
    ngx_memcpy(p, passwd.data, passwd.len);

    b->last = b->pos + NGX_LUA_DAHUA_HEADER_LEN;

    ctx->cmd = NGX_LUA_DAHUA_CMD_LOGIN_RESP;
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
    ngx_buf_t            *b;
    ngx_lua_thread_t     *thr;
    ngx_lua_dahua_ctx_t  *ctx;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua dahua ptz");

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

    b = ctx->request;
    b->pos = b->start;

    p = b->pos;
    ngx_memzero(p, NGX_LUA_DAHUA_HEADER_LEN);

    *p++ = NGX_LUA_DAHUA_CMD_PTZ;
    p += 8;

    *p++ = (u_char) (channel - 1);

    /* TODO: code */

    *p++ = (u_char) code;
    *p++ = 0x0A;
    *p++ = 5;

    b->last = b->pos + NGX_LUA_DAHUA_HEADER_LEN;

    ctx->cmd = NGX_LUA_DAHUA_CMD_PTZ_RESP;
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
ngx_lua_dahua_snapshot(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dahua_video(lua_State *l)
{
    int                     channel, type;
    char                   *errstr;
    ngx_int_t               rc;
    ngx_lua_thread_t       *thr;
    ngx_lua_dahua_ctx_t    *ctx;
    ngx_peer_connection_t  *peer;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua dahua video");

    channel = luaL_checkint(l, 2);
    type = luaL_checkint(l, 3);

    /* TODO: channel, type */

    ctx = ngx_lua_dahua(l);

    if (ctx->peer.connection == NULL) {
        errstr = "connection is null";
        goto error;
    }

    ctx->channel = channel;
    ctx->type = type;

    peer = &ctx->sub_peer;

    peer->sockaddr = ctx->u.addrs->sockaddr;
    peer->socklen = ctx->u.addrs->socklen;
    peer->name = &ctx->u.addrs->name;
    peer->get = ngx_event_get_peer;
    peer->log = ngx_cycle->log;
    peer->log_error = NGX_ERROR_ERR;
#if (NGX_THREADS)
    peer->lock = &thr->c->lock;
#endif

    rc = ngx_event_connect_peer(peer);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, thr->log, 0,
                   "lua dahua connecting to server: %i", rc);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        errstr = "ngx_event_connect_peer() failed";
        goto error;
    }

    peer->connection->data = ctx;
    peer->connection->pool = ctx->pool;

    peer->connection->read->handler = ngx_lua_dahua_dummy_handler;

    if (rc == NGX_OK) {
        peer->connection->write->handler = ngx_lua_dahua_dummy_handler;
        /* TODO */
        return 1;
    }

    /* rc == NGX_AGAIN */

    peer->connection->write->handler = ngx_lua_dahua_sub_connect_handler;

    ngx_add_timer(peer->connection->write, ctx->connect_timeout);

    return lua_yield(l, 0);

error:

    lua_pop(l, 1);
    lua_pushboolean(l, 0);
    lua_pushstring(l, errstr);

    return 2;
}


static int
ngx_lua_dahua_audio(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dahua_gc(lua_State *l)
{
    ngx_lua_dahua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "lua dahua gc");

    ctx = ngx_lua_dahua(l);

    if (ctx->cln_ctx != NULL) {
        ctx->cln_ctx->ctx = NULL;
    }

    ngx_lua_dahua_close(l);

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
    ngx_connection_t     *c;
    ngx_lua_thread_t     *thr;
    ngx_lua_dahua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, wev->log, 0,
                   "lua dahua connect handler");

    c = wev->data;
    ctx = c->data;
    thr = ctx->thr;

    if (thr == NULL) {
        return;
    }

    ctx->rc = 1;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
                      "lua dahua connecting %V timed out", ctx->peer.name);

        lua_pop(thr->l, 1);
        lua_pushboolean(thr->l, 0);
        lua_pushstring(thr->l, "ngx_lua_dahua_connect_handler() timed out");

        ctx->rc++;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    wev->handler = ngx_lua_dahua_dummy_handler;

    ctx->request = ngx_create_temp_buf(ctx->pool, ngx_pagesize);
    if (ctx->request == NULL) {
        lua_pop(thr->l, 1);
        lua_pushboolean(thr->l, 0);
        lua_pushstring(thr->l, "ngx_create_temp_buf() failed");

        ctx->rc++;
    }

    rc = ngx_lua_thread_run(thr, ctx->rc);
    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_lua_finalize(thr, rc);
}


static void
ngx_lua_dahua_write_handler(ngx_event_t *wev)
{
    char                 *errstr;
    size_t                size;
    u_char               *p;
    ssize_t               n;
    ngx_int_t             rc;
    ngx_buf_t            *b;
    ngx_connection_t     *c;
    ngx_lua_thread_t     *thr;
    ngx_lua_dahua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, wev->log, 0, "lua dahua write handler");

    c = wev->data;
    ctx = c->data;
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

    b = ctx->request;

    while (1) {

        size = b->last - b->pos;

        n = ngx_send(c, b->pos, size);

        if (n > 0) {
            b->pos += n;

            if ((size_t) n < size) {
                continue;
            }

            /* n == size */

            switch (ctx->cmd) {

            case NGX_LUA_DAHUA_CMD_LOGIN_RESP:
            case NGX_LUA_DAHUA_CMD_PTZ_RESP:
                wev->handler = ngx_lua_dahua_dummy_handler;

                ctx->rc = 0;

                ngx_lua_dahua_read_handler(c->read);

                if (ctx->rc == NGX_AGAIN) {
                    c->read->handler = ngx_lua_dahua_read_handler;
                    return;
                }

                break;

            case NGX_LUA_DAHUA_CMD_REG_SUB_CONN_RESP:
                wev->handler = ngx_lua_dahua_dummy_handler;

                b->pos = b->start;

                p = b->pos;
                ngx_memzero(p, NGX_LUA_DAHUA_HEADER_LEN + 16);

                *p = NGX_LUA_DAHUA_CMD_VIDEO;
                p += 4;

                *p = 16;
                p += 4;

                *(p + ctx->channel - 1) = 1;
                p += NGX_LUA_DAHUA_HEADER_LEN - 8;

                *(p + ctx->channel - 1) = (u_char) ctx->type - 1;

                b->last = b->pos + NGX_LUA_DAHUA_HEADER_LEN + 16;

                ctx->cmd = NGX_LUA_DAHUA_CMD_VIDEO_RESP;

                /* TODO */

                ngx_lua_dahua_write_handler(ctx->peer.connection->write);

                ctx->peer.connection->write->handler
                                                  = ngx_lua_dahua_write_handler;

                return;

            case NGX_LUA_DAHUA_CMD_VIDEO_RESP:
                b->pos = b->start;

                p = b->pos;
                ngx_memzero(p, NGX_LUA_DAHUA_HEADER_LEN);

                *p = NGX_LUA_DAHUA_CMD_HEART_BEAT;

                b->last = b->pos + NGX_LUA_DAHUA_HEADER_LEN;

                ctx->cmd = NGX_LUA_DAHUA_CMD_HEART_BEAT_RESP;

                ngx_lua_dahua_write_handler(wev);

                wev->handler = ngx_lua_dahua_write_handler;

                return;

            case NGX_LUA_DAHUA_CMD_HEART_BEAT_RESP:

                /* TODO */

                wev->handler = ngx_lua_dahua_dummy_handler;

                ctx->rc = 0;

#if 1
                ngx_lua_dahua_read_handler(ctx->sub_peer.connection->read);
#endif
                ngx_lua_dahua_read_handler(c->read);

                if (ctx->rc == NGX_AGAIN) {
                    ctx->sub_peer.connection->read->handler
                                                   = ngx_lua_dahua_read_handler;
                    c->read->handler = ngx_lua_dahua_read_handler;
                    return;
                }

                /* TODO */

                return;

            default:
                break;
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

    thr = ctx->thr;
    if (thr == NULL) {
        return;
    }

    ctx->rc = 1;

    if (n > 0) {
        lua_pushboolean(thr->l, 1);

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
ngx_lua_dahua_read_handler(ngx_event_t *rev)
{
    char                 *errstr;
    ssize_t               n;
    ngx_int_t             rc;
    ngx_buf_t            *b;
    ngx_connection_t     *c;
    ngx_lua_thread_t     *thr;
    ngx_lua_dahua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, rev->log, 0, "lua dahua read handler");

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

            if (ctx->cmd == NGX_LUA_DAHUA_CMD_LOGIN_RESP) {
                rc = ngx_lua_dahua_parse_login_response(ctx);

            } else if (ctx->cmd == NGX_LUA_DAHUA_CMD_PTZ_RESP) {
                /* TODO */
                rc = NGX_OK;

            } else if (ctx->cmd == NGX_LUA_DAHUA_CMD_HEART_BEAT_RESP) {
                rc = ngx_lua_dahua_parse_heart_beat_response(ctx);

            } else if (ctx->cmd == NGX_LUA_DAHUA_CMD_REG_SUB_CONN_RESP) {
                rc = ngx_lua_dahua_parse_reg_sub_conn_response(ctx);

            } else if (ctx->cmd == NGX_LUA_DAHUA_CMD_VIDEO_RESP) {
                rc = ngx_lua_dahua_parse_video_response(ctx);

            } else {
                rc = NGX_ERROR;
            }

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

    thr = ctx->thr;
    if (thr == NULL) {
        return;
    }

    ctx->rc = 1;

    if (n > 0) {
        lua_pushboolean(thr->l, 1);

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
ngx_lua_dahua_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "lua dahua dummy handler");
}


static void
ngx_lua_dahua_cleanup(void *data)
{
    ngx_lua_dahua_cleanup_ctx_t *cln_ctx = data;

    if (cln_ctx->ctx != NULL) {
        cln_ctx->ctx->thr = NULL;
        cln_ctx->ctx->cln_ctx = NULL;
    }
}


static ngx_int_t
ngx_lua_dahua_parse_login_response(ngx_lua_dahua_ctx_t *ctx)
{
    u_char     *p, ch;
    ngx_buf_t  *b;
    enum {
        sw_start = 0,
        sw_reserved,
        sw_extlen,
        sw_data_result,
        sw_data_error,
        sw_data_channels,
        sw_data_vcodec,
        sw_data_dev_type,
        sw_data_id_before,
        sw_data_id,
        sw_data_unused,
        sw_almost_done
    } state;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "lua dahua parse login response");

    b = ctx->response;
    state = ctx->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        case sw_start:
            if (ch != ctx->cmd) {
                return NGX_ERROR;
            }
            ctx->msg_start = p;
            state = sw_reserved;
            break;

        case sw_reserved:
            if (p - ctx->msg_start < 4) {
                break;
            }
            ctx->extlen_start = p;
            state = sw_extlen;
            break;

        case sw_extlen:
            if (p - ctx->extlen_start < 3) {
                break;
            }
            ctx->extlen = *((size_t *) ctx->extlen_start);
            state = sw_data_result;
            break;

        case sw_data_result:
            ctx->result = ch;
            state = sw_data_error;
            break;

        case sw_data_error:

            /* TODO: error handler */

            ctx->error = ch;
            state = sw_data_channels;
            break;

        case sw_data_channels:
            ctx->channel_n = ch;
            state = sw_data_vcodec;
            break;

        case sw_data_vcodec:
            ctx->vcodec = ch;
            state = sw_data_dev_type;
            break;

        case sw_data_dev_type:
            ctx->dev_type = ch;
            state = sw_data_id_before;
            break;

        case sw_data_id_before:
            if (p - ctx->msg_start < 16) {
                break;
            }
            ctx->id_start = p;
            state = sw_data_id;
            break;

        case sw_data_id:
            if (p - ctx->id_start < 3) {
                break;
            }
            ngx_memcpy(ctx->id, ctx->id_start, sizeof(ctx->id));
            state = sw_data_unused;
            break;

        case sw_data_unused:
            if (p - ctx->msg_start < NGX_LUA_DAHUA_HEADER_LEN - 2) {
                break;
            }
            state = sw_almost_done;
            break;

        case sw_almost_done:
            goto done;
        }
    }

    b->pos = p;
    ctx->state = state;

    return NGX_AGAIN;

done:

    b->pos = p + 1;
    ctx->state = 0;
    ctx->cmd = 0;

    if (b->pos != b->last) {
        /* TODO: return NGX_ERROR; */
    }

    b->pos = b->start;
    b->last = b->start;

    return NGX_OK;
}


static ngx_int_t
ngx_lua_dahua_parse_heart_beat_response(ngx_lua_dahua_ctx_t *ctx)
{
    u_char      *p, ch;
    ngx_buf_t   *b;
    ngx_uint_t   n;
    enum {
        sw_start = 0,
        sw_reserved_1,
        sw_reserved_2,
        sw_reserved_3,
        sw_ext_len_4,
        sw_ext_len_5,
        sw_ext_len_6,
        sw_ext_len_7,
        sw_unused_8,
        sw_unused_9,
        sw_unused_10,
        sw_unused_11,
        sw_unused_12,
        sw_unused_13,
        sw_unused_14,
        sw_unused_15,
        sw_unused_16,
        sw_unused_17,
        sw_unused_18,
        sw_unused_19,
        sw_unused_20,
        sw_unused_21,
        sw_unused_22,
        sw_unused_23,
        sw_unused_24,
        sw_unused_25,
        sw_unused_26,
        sw_unused_27,
        sw_unused_28,
        sw_unused_29,
        sw_unused_30,
        sw_almost_done
    } state;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "lua dahua parse heart beat response");

    b = ctx->response;
    n = 0;
    state = ctx->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        case sw_start:
            if (ch != ctx->cmd) {
                return NGX_ERROR;
            }
            state = sw_reserved_1;
            break;

        case sw_reserved_1:
            state = sw_reserved_2;
            break;

        case sw_reserved_2:
            state = sw_reserved_3;
            break;

        case sw_reserved_3:
            state = sw_ext_len_4;
            break;

        case sw_ext_len_4:
            ctx->extlen = 0;
            ctx->extlen |= ch;
            state = sw_ext_len_5;
            break;

        case sw_ext_len_5:
            ctx->extlen |= ch << 8;
            state = sw_ext_len_6;
            break;

        case sw_ext_len_6:
            ctx->extlen |= ch << 16;
            state = sw_ext_len_7;
            break;

        case sw_ext_len_7:
            ctx->extlen |= ch << 24;
#if 0
            ctx->count = ctx->extlen;
#endif
            state = sw_unused_8;
            break;

        case sw_unused_8:
            state = sw_unused_9;
            break;

        case sw_unused_9:
            state = sw_unused_10;
            break;

        case sw_unused_10:
            state = sw_unused_11;
            break;

        case sw_unused_11:
            state = sw_unused_12;
            break;

        case sw_unused_12:
            state = sw_unused_13;
            break;

        case sw_unused_13:
            state = sw_unused_14;
            break;

        case sw_unused_14:
            state = sw_unused_15;
            break;

        case sw_unused_15:
            state = sw_unused_16;
            break;

        case sw_unused_16:
            state = sw_unused_17;
            break;

        case sw_unused_17:
            state = sw_unused_18;
            break;

        case sw_unused_18:
            state = sw_unused_19;
            break;

        case sw_unused_19:
            state = sw_unused_20;
            break;

        case sw_unused_20:
            state = sw_unused_21;
            break;

        case sw_unused_21:
            state = sw_unused_22;
            break;

        case sw_unused_22:
            state = sw_unused_23;
            break;

        case sw_unused_23:
            state = sw_unused_24;
            break;

        case sw_unused_24:
            state = sw_unused_25;
            break;

        case sw_unused_25:
            state = sw_unused_26;
            break;

        case sw_unused_26:
            state = sw_unused_27;
            break;

        case sw_unused_27:
            state = sw_unused_28;
            break;

        case sw_unused_28:
            state = sw_unused_29;
            break;

        case sw_unused_29:
            state = sw_unused_30;
            break;

        case sw_unused_30:
            state = sw_almost_done;
            break;

        case sw_almost_done:
            goto done;
        }
    }

    b->pos = p;
    ctx->state = state;

    if (b->last == b->end) {
        b->pos = b->start;
        b->last = b->start;
    }

    return NGX_AGAIN;

done:

    ctx->cmd = 0;
    b->pos = p + 1;
    ctx->state = 0;

    if (b->pos < b->last) {
        return NGX_OK;
    }

    if (b->last == b->end) {
        b->pos = b->start;
        b->last = b->start;
    }

#if 1
    ctx->cmd = NGX_LUA_DAHUA_CMD_VIDEO_RESP;
    ctx->peer.connection->read->handler(ctx->peer.connection->read);
    return NGX_AGAIN;
#else
    return NGX_OK;
#endif
}


static ngx_int_t
ngx_lua_dahua_parse_reg_sub_conn_response(ngx_lua_dahua_ctx_t *ctx)
{
    u_char     *p, ch;
    ngx_buf_t  *b;
    enum {
        sw_start = 0,
        sw_reserved,
        sw_extlen,
        sw_data_result,
        sw_data_error,
        sw_data_channels,
        sw_data_vcodec,
        sw_data_dev_type,
        sw_data_id_before,
        sw_data_id,
        sw_data_unused,
        sw_almost_done
    } state;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "lua dahua parse reg sub conn response");

    b = ctx->response;
    state = ctx->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        case sw_start:
            if (ch != ctx->cmd) {
                return NGX_ERROR;
            }
            ctx->msg_start = p;
            state = sw_reserved;
            break;

        case sw_reserved:
            if (p - ctx->msg_start < 4) {
                break;
            }
            ctx->extlen_start = p;
            state = sw_extlen;
            break;

        case sw_extlen:
            if (p - ctx->extlen_start < 3) {
                break;
            }
            ctx->extlen = *((size_t *) ctx->extlen_start);
            state = sw_data_result;
            break;

        case sw_data_result:
            ctx->result = ch;
            state = sw_data_error;
            break;

        case sw_data_error:

            /* TODO: error handler */

            ctx->error = ch;
            state = sw_data_channels;
            break;

        case sw_data_channels:
            ctx->channel_n = ch;
            state = sw_data_vcodec;
            break;

        case sw_data_vcodec:
            ctx->vcodec = ch;
            state = sw_data_dev_type;
            break;

        case sw_data_dev_type:
            ctx->dev_type = ch;
            state = sw_data_id_before;
            break;

        case sw_data_id_before:
            if (p - ctx->msg_start < 16) {
                break;
            }
            ctx->id_start = p;
            state = sw_data_id;
            break;

        case sw_data_id:
            if (p - ctx->id_start < 3) {
                break;
            }
            ngx_memcpy(ctx->id, ctx->id_start, sizeof(ctx->id));
            state = sw_data_unused;
            break;

        case sw_data_unused:
            if (p - ctx->msg_start < NGX_LUA_DAHUA_HEADER_LEN - 2) {
                break;
            }
            state = sw_almost_done;
            break;

        case sw_almost_done:
            goto done;
        }
    }

    b->pos = p;
    ctx->state = state;

    return NGX_AGAIN;

done:

    b->pos = p + 1;
    ctx->state = 0;
    ctx->cmd = 0;

    if (b->pos != b->last) {
        /* TODO: return NGX_ERROR; */
    }

    b->pos = b->start;
    b->last = b->start;

    return NGX_OK;
}


static ngx_int_t
ngx_lua_dahua_parse_video_response(ngx_lua_dahua_ctx_t *ctx)
{
#if 0
    u_char      *p, ch;
    ngx_buf_t   *b;
    ngx_uint_t   n;
    enum {
        sw_start = 0,
        sw_reserved,
        sw_extlen,
        sw_channel,
        sw_data_seq_9,
        sw_data_seq_10,
        sw_data_seq_11,
        sw_data_seq_12,
        sw_unused_13,
        sw_unused_14,
        sw_unused_15,
        sw_return_code,
        sw_unused_17,
        sw_unused_18,
        sw_unused_19,
        sw_unused_20,
        sw_unused_21,
        sw_unused_22,
        sw_unused_23,
        sw_unused_24,
        sw_unused_25,
        sw_unused_26,
        sw_unused_27,
        sw_unused_28,
        sw_unused_29,
        sw_unused_30,
        sw_unused_31,
        sw_fh_flag1,
        sw_fh_flag2,
        sw_fh_flag3,
        sw_fh_flag4,
        sw_fh_unused,
        sw_fh_rate,
        sw_fh_width,
        sw_fh_height,
        sw_fh_dt1,
        sw_fh_dt2,
        sw_fh_dt3,
        sw_fh_dt4,
        sw_fh_len_1,
        sw_fh_len_2,
        sw_fh_len_3,
        sw_fh_len_4,
        sw_frame_data,
        sw_almost_done
    } state;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "lua dahua parse video response");

    b = ctx->response;
    n = 0;
    state = ctx->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        case sw_start:
            if (ch != ctx->command) {
                return NGX_ERROR;
            }

            state = sw_reserved_1;
            break;

        case sw_reserved_1:
            state = sw_reserved_2;
            break;

        case sw_reserved_2:
            state = sw_reserved_3;
            break;

        case sw_reserved_3:
            state = sw_ext_len_4;
            break;

        case sw_ext_len_4:
            ctx->ext_len = 0;
            ctx->ext_len |= ch;

            state = sw_ext_len_5;
            break;

        case sw_ext_len_5:
            ctx->ext_len |= ch << 8;

            state = sw_ext_len_6;
            break;

        case sw_ext_len_6:
            ctx->ext_len |= ch << 16;

            state = sw_ext_len_7;
            break;

        case sw_ext_len_7:
            ctx->ext_len |= ch << 24;

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                           "length of ext data: %uz", ctx->ext_len);

            state = sw_channel;
            break;

        case sw_channel:
            state = sw_data_seq_9;
            break;

        case sw_data_seq_9:
            ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                           "data sequence: %ui", (ngx_uint_t) ch);

            state = sw_data_seq_10;
            break;

        case sw_data_seq_10:
            state = sw_data_seq_11;
            break;

        case sw_data_seq_11:
            state = sw_data_seq_12;
            break;

        case sw_data_seq_12:
            state = sw_unused_13;
            break;

        case sw_unused_13:
            state = sw_unused_14;
            break;

        case sw_unused_14:
            state = sw_unused_15;
            break;

        case sw_unused_15:
            state = sw_return_code;
            break;

        case sw_return_code:
            state = sw_unused_17;
            break;

        case sw_unused_17:
            state = sw_unused_18;
            break;

        case sw_unused_18:
            state = sw_unused_19;
            break;

        case sw_unused_19:
            state = sw_unused_20;
            break;

        case sw_unused_20:
            state = sw_unused_21;
            break;

        case sw_unused_21:
            state = sw_unused_22;
            break;

        case sw_unused_22:
            state = sw_unused_23;
            break;

        case sw_unused_23:
            state = sw_unused_24;
            break;

        case sw_unused_24:
            state = sw_unused_25;
            break;

        case sw_unused_25:
            state = sw_unused_26;
            break;

        case sw_unused_26:
            state = sw_unused_27;
            break;

        case sw_unused_27:
            state = sw_unused_28;
            break;

        case sw_unused_28:
            state = sw_unused_29;
            break;

        case sw_unused_29:
            state = sw_unused_30;
            break;

        case sw_unused_30:
            state = sw_unused_31;
            break;

        case sw_unused_31:
            state = sw_fh_flag1;
            break;

        case sw_fh_flag1:
            if (ch != 0x00) {
                return NGX_ERROR;
            }

            state = sw_fh_flag2;
            break;

        case sw_fh_flag2:
            if (ch != 0x00) {
                return NGX_ERROR;
            }

            state = sw_fh_flag3;
            break;

        case sw_fh_flag3:
            if (ch != 0x01) {
                return NGX_ERROR;
            }

            state = sw_fh_flag4;
            break;

        case sw_fh_flag4:
            if (ch == 0xfc) {
                state = sw_fh_len_1;
                break;
            }

            if (ch == 0xfd) {
                state = sw_fh_unused;
                break;
            }

            return NGX_ERROR;

        case sw_fh_unused:
            state = sw_fh_rate;
            break;

        case sw_fh_rate:
            ctx->src_rate = ch & 0x1F;
            state = sw_fh_width;
            break;

        case sw_fh_width:
            ctx->src_width = ch * 8;
            state = sw_fh_height;
            break;

        case sw_fh_height:
            ctx->src_height = ch * 8;

            /* TODO */

            ctx->dst_width = 400;
            ctx->dst_height = 300;
            ctx->dst_rate = ctx->src_rate;

            if (ngx_stream_dahua_av_init(s, ctx) != NGX_OK) {
                return NGX_ERROR;
            }

            if (ngx_stream_dahua_av_open(s, ctx) != NGX_OK) {
                return NGX_ERROR;
            }

            state = sw_fh_dt1;
            break;

        case sw_fh_dt1:
            ctx->frame_dt = 0;
            ctx->frame_dt |= ch;

            state = sw_fh_dt2;
            break;

        case sw_fh_dt2:
            ctx->frame_dt |= ch << 8;

            state = sw_fh_dt3;
            break;

        case sw_fh_dt3:
            ctx->frame_dt |= ch << 16;

            state = sw_fh_dt4;
            break;

        case sw_fh_dt4:
            ctx->frame_dt |= ch << 24;

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, s->pool->log, 0,
                           "%d-%d-%d %d:%d:%d",
                           (ctx->frame_dt >> 26) + 2000,
                           ctx->frame_dt >> 22 & 0x0f,
                           ctx->frame_dt >> 17 & 0x1f,
                           ctx->frame_dt >> 12 & 0x1f,
                           ctx->frame_dt >> 6 & 0x3f,
                           ctx->frame_dt & 0x3f);

            state = sw_fh_len_1;
            break;

        case sw_fh_len_1:
            ctx->frame_len = 0;
            ctx->frame_len |= ch;

            state = sw_fh_len_2;
            break;

        case sw_fh_len_2:
            ctx->frame_len |= ch << 8;

            state = sw_fh_len_3;
            break;

        case sw_fh_len_3:
            ctx->frame_len |= ch << 16;

            state = sw_fh_len_4;
            break;

        case sw_fh_len_4:
            ctx->frame_len |= ch << 24;

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                           "length of frame data: %uz", ctx->frame_len);

            ctx->count = ctx->frame_len;

            state = sw_frame_data;
            break;

        case sw_frame_data:
            if (ctx->frame == NULL) {
                ctx->frame = ngx_create_temp_buf(s->pool, 128 * ngx_pagesize);
                if (ctx->frame == NULL) {
                    return NGX_ERROR;
                }
            }

            n++;

            if (ctx->count-- > 2) {
                break;
            }

            state = sw_almost_done;
            break;

        case sw_almost_done:
            n++;

            ctx->frame->last = ngx_copy(ctx->frame->last, p - n + 1, n);

            goto done;
        }
    }

    if (n > 0) {
        ctx->frame->last = ngx_copy(ctx->frame->last, p - n, n);
    }

    buf->pos = p;
    s->state = state;

    if (buf->last == buf->end) {
        buf->pos = buf->start;
        buf->last = buf->start;
    }

    return NGX_AGAIN;

done:

#if 0
    {
    u_char  temp[8192], *last;

    last = ngx_hex_dump(temp, ctx->frame->pos,
                        ctx->frame->last - ctx->frame->pos);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "%*s", last - temp, temp);
    }
#endif

    ctx->frame->last = ctx->frame->start;

    ctx->command = 0;

    buf->pos = p + 1;
    s->state = 0;

    if (buf->pos < buf->last) {
        return NGX_OK;
    }

    if (buf->last == buf->end) {
        buf->pos = buf->start;
        buf->last = buf->start;
    }

    if (ngx_current_msec - ctx->last_bh > 2000) {
        ctx->last_bh = ngx_current_msec;

        if (ngx_stream_dahua_send_heart_beat_request(s, ctx) == NGX_OK) {
            return NGX_OK;
        }
    }

    c->read->handler(c->read);
#endif

    return NGX_OK;
}


static void
ngx_lua_dahua_sub_connect_handler(ngx_event_t *wev)
{
    char                 *errstr;
    u_char               *p;
    ngx_int_t             rc;
    ngx_buf_t            *b;
    ngx_connection_t     *c;
    ngx_lua_thread_t     *thr;
    ngx_lua_dahua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, wev->log, 0,
                   "lua dahua sub connect handler");

    c = wev->data;
    ctx = c->data;
    thr = ctx->thr;

    if (thr == NULL) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
                      "lua dahua connecting %V timed out", ctx->peer.name);
        errstr = "ngx_lua_dahua_connect_handler() timed out";
        goto error;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    wev->handler = ngx_lua_dahua_dummy_handler;

    b = ctx->request;
    b->pos = b->start;

    p = b->pos;
    ngx_memzero(p, NGX_LUA_DAHUA_HEADER_LEN);

    *p = NGX_LUA_DAHUA_CMD_REG_SUB_CONN;
    p += 7;

    p = ngx_cpymem(p, ctx->id, sizeof(ctx->id));

    *p++ = 1;

    *p = (u_char) (ctx->channel - 1);

    b->last = b->pos + NGX_LUA_DAHUA_HEADER_LEN;

    ctx->cmd = NGX_LUA_DAHUA_CMD_REG_SUB_CONN_RESP;
    ctx->rc = 0;
    ctx->not_event = 1;

    ngx_lua_dahua_write_handler(wev);

    ctx->not_event = 0;

    if (ctx->rc != NGX_AGAIN) {
        /* TODO */
        return;
    }

    wev->handler = ngx_lua_dahua_write_handler;

    return;

error:

    lua_pushboolean(thr->l, 0);
    lua_pushstring(thr->l, errstr);

    rc = ngx_lua_thread_run(thr, 2);
    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_lua_finalize(thr, rc);
}


static ngx_int_t
ngx_lua_dahua_module_init(ngx_cycle_t *cycle)
{
    int              n;
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua dahua module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    lua_getglobal(lcf->l, NGX_LUA_TABLE);

    luaL_newmetatable(lcf->l, NGX_LUA_DAHUA);
    lua_pushvalue(lcf->l, -1);
    lua_setfield(lcf->l, -2, "__index");

    for (n = 0; ngx_lua_dahua_methods[n].name != NULL; n++) {
        lua_pushcfunction(lcf->l, ngx_lua_dahua_methods[n].func);
        lua_setfield(lcf->l, -2, ngx_lua_dahua_methods[n].name);
    }

    lua_pop(lcf->l, 1);

    n = sizeof(ngx_lua_dahua_consts) / sizeof(ngx_lua_const_t) - 1;
    n += 1;

    lua_createtable(lcf->l, 0, n);

    for (n = 0; ngx_lua_dahua_consts[n].name != NULL; n++) {
        lua_pushinteger(lcf->l, ngx_lua_dahua_consts[n].value);
        lua_setfield(lcf->l, -2, ngx_lua_dahua_consts[n].name);
    }

    lua_pushcfunction(lcf->l, ngx_lua_dahua_open);
    lua_setfield(lcf->l, -2, "open");

    lua_setfield(lcf->l, -2, "dahua");

    lua_pop(lcf->l, 1);

    return NGX_OK;
}
