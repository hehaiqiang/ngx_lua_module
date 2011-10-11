
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua.h>


#define NGX_LUA_FILE  "ngx_lua_file_ctx_t*"


typedef struct ngx_lua_file_cleanup_ctx_s  ngx_lua_file_cleanup_ctx_t;


typedef struct {
    ngx_pool_t                    *pool;
    ngx_file_t                     file;
    ngx_buf_t                     *in;
    ngx_buf_t                     *out;
    ngx_lua_thread_t              *thr;
    ngx_lua_file_cleanup_ctx_t    *cln_ctx;
} ngx_lua_file_ctx_t;


struct ngx_lua_file_cleanup_ctx_s {
    ngx_lua_file_ctx_t            *ctx;
};


static int ngx_lua_file_open(lua_State *l);
static int ngx_lua_file_close(lua_State *l);
static int ngx_lua_file_read(lua_State *l);
static int ngx_lua_file_write(lua_State *l);
#if 0
static int ngx_lua_file_index(lua_State *l);
#endif
static int ngx_lua_file_gc(lua_State *l);
static int ngx_lua_file_info(lua_State *l);

static ngx_inline ngx_lua_file_ctx_t *ngx_lua_file(lua_State *l);

static void ngx_lua_file_read_handler(ngx_event_t *ev);
#if (NGX_WIN32)
static void ngx_lua_file_write_handler(ngx_event_t *ev);
#endif

static void ngx_lua_file_cleanup(void *data);

static ngx_int_t ngx_lua_file_module_init(ngx_cycle_t *cycle);


static ngx_lua_const_t  ngx_lua_file_consts[] = {
    { "RDONLY", NGX_FILE_RDONLY },
    { "WRONLY", NGX_FILE_WRONLY },
    { "RDWR", NGX_FILE_RDWR },
    { "APPEND", NGX_FILE_APPEND },

    { "CREATE_OR_OPEN", NGX_FILE_CREATE_OR_OPEN },
    { "OPEN", NGX_FILE_OPEN },
    { "TRUNCATE", NGX_FILE_TRUNCATE },

    { "DEFAULT_ACCESS", NGX_FILE_DEFAULT_ACCESS },
    { "OWNER_ACCESS", NGX_FILE_OWNER_ACCESS },

    { NULL, 0 }
};


static luaL_Reg  ngx_lua_file_methods[] = {
    { "close", ngx_lua_file_close },
    { "read", ngx_lua_file_read },
    { "write", ngx_lua_file_write },
#if 0
    { "__index", ngx_lua_file_index },
#endif
    { "__gc", ngx_lua_file_gc },
    { NULL, NULL }
};


ngx_module_t  ngx_lua_file_module = {
    NGX_MODULE_V1,
    NULL,                                  /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_lua_file_module_init,              /* init module */
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
        &ngx_lua_file_module,
        NULL
    };

    return modules;
}
#endif


static int
ngx_lua_file_open(lua_State *l)
{
    int                           mode, create, access;
    char                         *errstr;
    u_char                       *name;
    ngx_pool_t                   *pool;
    ngx_file_t                   *file;
    ngx_lua_thread_t             *thr;
    ngx_pool_cleanup_t           *cln;
    ngx_lua_file_ctx_t          **ctx;
    ngx_lua_file_cleanup_ctx_t   *cln_ctx;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua file open");

    name = (u_char *) luaL_checkstring(l, 1);
    mode = (int) luaL_optnumber(l, 2, NGX_FILE_RDWR);
    create = (int) luaL_optnumber(l, 3, NGX_FILE_CREATE_OR_OPEN);
    access = (int) luaL_optnumber(l, 4, NGX_FILE_DEFAULT_ACCESS);

    mode |= NGX_FILE_NONBLOCK;

#if (NGX_WIN32 && NGX_HAVE_FILE_AIO)
    if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
        mode |= NGX_FILE_OVERLAPPED;
    }
#endif

    ctx = lua_newuserdata(l, sizeof(ngx_lua_file_ctx_t *));
    luaL_getmetatable(l, NGX_LUA_FILE);
    lua_setmetatable(l, -2);

    *ctx = NULL;

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
        errstr = "ngx_create_pool() failed";
        goto error;
    }

    *ctx = ngx_pcalloc(pool, sizeof(ngx_lua_file_ctx_t));
    if (*ctx == NULL) {
        ngx_destroy_pool(pool);
        errstr = "ngx_pcalloc() failed";
        goto error;
    }

    (*ctx)->pool = pool;

    cln_ctx = ngx_pcalloc(thr->pool, sizeof(ngx_lua_file_cleanup_ctx_t));
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

    cln->handler = ngx_lua_file_cleanup;
    cln->data = cln_ctx;

    (*ctx)->thr = thr;
    (*ctx)->cln_ctx = cln_ctx;

    file = &(*ctx)->file;

    file->fd = ngx_open_file(name, mode, create, access);
    if (file->fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ALERT, thr->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", name);
        errstr = ngx_open_file_n " failed";
        goto error;
    }

    file->log = ngx_cycle->log;

    return 1;

error:

    lua_pop(l, 1);
    lua_pushboolean(l, 0);
    lua_pushstring(l, errstr);

    return 2;
}


static int
ngx_lua_file_close(lua_State *l)
{
    ngx_lua_thread_t    *thr;
    ngx_lua_file_ctx_t  *ctx;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua file close");

    ctx = ngx_lua_file(l);

    if (ctx->file.fd != NGX_INVALID_FILE) {
        ngx_close_file(ctx->file.fd);
        ctx->file.fd = NGX_INVALID_FILE;
    }

    return 0;
}


static int
ngx_lua_file_read(lua_State *l)
{
    char                *errstr;
    off_t                offset;
    size_t               size, buf_size;
    ssize_t              n;
    ngx_buf_t           *b;
    ngx_file_t          *file;
    ngx_file_info_t      fi;
    ngx_lua_thread_t    *thr;
    ngx_lua_file_ctx_t  *ctx;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua file read");

    ctx = ngx_lua_file(l);

    file = &ctx->file;

    if (file->fd == NGX_INVALID_FILE) {
        errstr = "invalid fd";
        goto error;
    }

    ngx_memzero(&fi, sizeof(ngx_file_info_t));

    if (ngx_fd_info(file->fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, thr->log, ngx_errno,
                      ngx_fd_info_n " failed");
        errstr = ngx_fd_info_n " failed";
        goto error;
    }

    size = (size_t) ngx_file_size(&fi);

    offset = (off_t) luaL_optnumber(l, 3, (lua_Number) file->offset);
    size = (size_t) luaL_optnumber(l, 2, (lua_Number) (size - offset));

    if (size <= 0 || offset < 0) {
        errstr = "invalid size or offset of the file or the file is empty";
        goto error;
    }

    b = ctx->in;

    if (b == NULL || (size_t) (b->end - b->start) < size) {
        if (b != NULL && (size_t) (b->end - b->start) > ctx->pool->max) {
            ngx_pfree(ctx->pool, b->start);
        }

        buf_size = ngx_max(ngx_pagesize, size);

        b = ngx_create_temp_buf(ctx->pool, buf_size);
        if (b == NULL) {
            errstr = "ngx_create_temp_buf() failed";
            goto error;
        }

        ctx->in = b;
    }

    b->last = b->pos;

    n = ngx_file_aio_read(file, b->last, size, offset, ctx->pool);

    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, thr->log, ngx_errno,
                      "ngx_file_aio_read() failed");
        errstr = "ngx_file_aio_read() failed";
        goto error;
    }

    if (n == NGX_AGAIN) {
        ctx->file.aio->data = ctx;
        ctx->file.aio->handler = ngx_lua_file_read_handler;
        return lua_yield(l, 0);
    }

    /* n > 0 */

    lua_pushlstring(l, (char *) b->pos, n);

    return 1;

error:

    lua_pushboolean(l, 0);
    lua_pushstring(l, errstr);

    return 2;
}


static int
ngx_lua_file_write(lua_State *l)
{
    char                *errstr;
    off_t                offset;
    size_t               size;
    ssize_t              n;
    ngx_str_t            str;
    ngx_buf_t           *b;
    ngx_file_t          *file;
    ngx_lua_thread_t    *thr;
    ngx_lua_file_ctx_t  *ctx;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua file write");

    ctx = ngx_lua_file(l);

    file = &ctx->file;

    if (file->fd == NGX_INVALID_FILE) {
        errstr = "invalid fd";
        goto error;
    }

    str.data = (u_char *) luaL_checklstring(l, 2, &str.len);
    offset = (off_t) luaL_optnumber(l, 3, (lua_Number) file->offset);

    if (offset < 0) {
        errstr = "invalid offset of the file";
        goto error;
    }

    b = ctx->out;

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

        ctx->out = b;
    }

    b->pos = b->start;
    b->last = ngx_cpymem(b->pos, str.data, str.len);

#if (NGX_WIN32)

    n = ngx_file_aio_write(file, b->pos, str.len, offset, ctx->pool);

    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, thr->log, ngx_errno,
                      "ngx_file_aio_write() failed");
        errstr = "ngx_file_aio_write() failed";
        goto error;
    }

    if (n == NGX_AGAIN) {
        ctx->file.aio->data = ctx;
        ctx->file.aio->handler = ngx_lua_file_write_handler;
        return lua_yield(l, 0);
    }

    /* n > 0 */

    if ((size_t) n != str.len) {
        errstr = "ngx_file_aio_write() n != str.len";
        goto error;
    }

#else

    /* TODO: AIO write for linux, freebsd and solaris, etc */

    n = ngx_write_file(file, b->pos, str.len, offset);

    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, thr->log, ngx_errno,
                      "ngx_write_file() failed");
        errstr = "ngx_write_file() failed";
        goto error;
    }

#endif

    /* n > 0 */

    lua_pushnumber(l, n);

    return 1;

error:

    lua_pushboolean(l, 0);
    lua_pushstring(l, errstr);

    return 2;
}


#if 0
static int
ngx_lua_file_index(lua_State *l)
{
    ngx_str_t            key;
    ngx_file_info_t      fi;
    ngx_http_request_t  *r;
    ngx_lua_file_ctx_t  *ctx;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "lua file index");

    key.data = (u_char *) luaL_checklstring(l, -1, &key.len);

    switch (key.len) {

    case 4:

        if (ngx_strncmp(key.data, "size", 4) == 0) {
            ctx = ngx_lua_file(l);

            ngx_memzero(&fi, sizeof(ngx_file_info_t));

            if (ngx_fd_info(ctx->file.fd, &fi) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                              ngx_fd_info_n " failed");
                lua_pushnil(l);
                lua_pushstring(l, ngx_fd_info_n " failed");
                return 1;
            }

            lua_pushnumber(l, (lua_Number) ngx_file_size(&fi));

            return 1;
        }

        break;

    case 10:

        if (ngx_strncmp(key.data, "attributes", 10) == 0) {
            /* TODO */
        }

        break;

    default:
        break;
    }

    return 0;
}
#endif


static int
ngx_lua_file_gc(lua_State *l)
{
    ngx_lua_file_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "lua file gc");

    ctx = ngx_lua_file(l);

    if (ctx->file.fd != NGX_INVALID_FILE) {
        ngx_close_file(ctx->file.fd);
        ctx->file.fd = NGX_INVALID_FILE;
    }

    ngx_destroy_pool(ctx->pool);

    return 0;
}


static int
ngx_lua_file_info(lua_State *l)
{
    ngx_lua_thread_t  *thr;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua file info");

    /* TODO */

    return 0;
}


static ngx_inline ngx_lua_file_ctx_t *
ngx_lua_file(lua_State *l)
{
    ngx_lua_file_ctx_t  **ctx;

    ctx = luaL_checkudata(l, 1, NGX_LUA_FILE);
    if (*ctx == NULL) {
        luaL_error(l, "ngx_lua_file() *ctx == NULL");
    }

    return *ctx;
}


static void
ngx_lua_file_read_handler(ngx_event_t *ev)
{
    ngx_int_t            rc;
    ngx_event_aio_t     *aio;
    ngx_lua_file_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "lua file read handler");

    aio = ev->data;
    ctx = aio->data;

    ev->complete = 0;

    /* TODO: error handling */

    if (ctx->thr == NULL) {
        return;
    }

    lua_pushlstring(ctx->thr->l, (char *) ctx->in->pos, ev->available);

    ctx->file.offset += ev->available;

    rc = ngx_lua_thread_run(ctx->thr, 1);
    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_lua_finalize(ctx->thr, rc);
}


#if (NGX_WIN32)

static void
ngx_lua_file_write_handler(ngx_event_t *ev)
{
    ngx_int_t            rc;
    ngx_event_aio_t     *aio;
    ngx_lua_file_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "lua file write handler");

    aio = ev->data;
    ctx = aio->data;

    ev->complete = 0;

    /* TODO: error handling */

    if (ctx->thr == NULL) {
        return;
    }

    lua_pushnumber(ctx->thr->l, ev->available);

    ctx->file.offset += ev->available;

    rc = ngx_lua_thread_run(ctx->thr, 1);
    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_lua_finalize(ctx->thr, rc);
}

#endif


static void
ngx_lua_file_cleanup(void *data)
{
    ngx_lua_file_cleanup_ctx_t *cln_ctx = data;

    if (cln_ctx->ctx != NULL) {
        cln_ctx->ctx->thr = NULL;
        cln_ctx->ctx->cln_ctx = NULL;
    }
}


static ngx_int_t
ngx_lua_file_module_init(ngx_cycle_t *cycle)
{
    int              n;
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua file module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    lua_getglobal(lcf->l, "nginx");

    luaL_newmetatable(lcf->l, NGX_LUA_FILE);
    lua_pushvalue(lcf->l, -1);
    lua_setfield(lcf->l, -2, "__index");

    for (n = 0; ngx_lua_file_methods[n].name != NULL; n++) {
        lua_pushcfunction(lcf->l, ngx_lua_file_methods[n].func);
        lua_setfield(lcf->l, -2, ngx_lua_file_methods[n].name);
    }

    lua_pop(lcf->l, 1);

    n = sizeof(ngx_lua_file_consts) / sizeof(ngx_lua_const_t) - 1;
    n += 2;

    lua_createtable(lcf->l, 0, n);

    for (n = 0; ngx_lua_file_consts[n].name != NULL; n++) {
        lua_pushinteger(lcf->l, ngx_lua_file_consts[n].value);
        lua_setfield(lcf->l, -2, ngx_lua_file_consts[n].name);
    }

    lua_pushcfunction(lcf->l, ngx_lua_file_open);
    lua_setfield(lcf->l, -2, "open");
    lua_pushcfunction(lcf->l, ngx_lua_file_info);
    lua_setfield(lcf->l, -2, "attributes");

    lua_setfield(lcf->l, -2, "file");

    lua_pop(lcf->l, 1);

    return NGX_OK;
}
