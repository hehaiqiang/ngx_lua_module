
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_module.h>


#define NGX_LUA_FILE  "ngx_lua_file_ctx_t*"


typedef struct {
    ngx_pool_t            *pool;
    ngx_file_t             file;
    ngx_buf_t             *in;
    ngx_buf_t             *out;
    ngx_http_request_t    *r;
} ngx_lua_file_ctx_t;


static int ngx_lua_file_open(lua_State *l);
static int ngx_lua_file_close(lua_State *l);
static int ngx_lua_file_read(lua_State *l);
static int ngx_lua_file_write(lua_State *l);
static int ngx_lua_file_size(lua_State *l);
static int ngx_lua_file_gc(lua_State *l);

static ngx_inline ngx_lua_file_ctx_t *ngx_lua_file(lua_State *l);

static void ngx_lua_file_read_handler(ngx_event_t *ev);
#if (NGX_WIN32)
static void ngx_lua_file_write_handler(ngx_event_t *ev);
#endif


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
    { "size", ngx_lua_file_size },
    { "__gc", ngx_lua_file_gc },
    { NULL, NULL }
};


void
ngx_lua_file_api_init(lua_State *l)
{
    int  n;

    luaL_newmetatable(l, NGX_LUA_FILE);
    lua_pushvalue(l, -1);
    lua_setfield(l, -2, "__index");

    for (n = 0; ngx_lua_file_methods[n].name != NULL; n++) {
        lua_pushcfunction(l, ngx_lua_file_methods[n].func);
        lua_setfield(l, -2, ngx_lua_file_methods[n].name);
    }

    lua_pop(l, 1);

    n = sizeof(ngx_lua_file_consts) / sizeof(ngx_lua_const_t) - 1;
    n += 1;

    lua_createtable(l, 0, n);

    for (n = 0; ngx_lua_file_consts[n].name != NULL; n++) {
        lua_pushinteger(l, ngx_lua_file_consts[n].value);
        lua_setfield(l, -2, ngx_lua_file_consts[n].name);
    }

    lua_pushcfunction(l, ngx_lua_file_open);
    lua_setfield(l, -2, "open");

    lua_setfield(l, -2, "file");
}


static int
ngx_lua_file_open(lua_State *l)
{
    int                   n, mode, create, access;
    char                 *errstr;
    u_char               *name;
    ngx_pool_t           *pool;
    ngx_file_t           *file;
    ngx_lua_file_ctx_t  **ctx;
    ngx_http_request_t   *r;

    r = ngx_lua_request(l);

    n = lua_gettop(l);

    name = (u_char *) luaL_checkstring(l, 1);

    /* mode, create, access */

    if (n >= 2) {
        mode = luaL_checkint(l, 2);

    } else {
        mode = NGX_FILE_RDWR;
    }

    if (n >= 3) {
        create = luaL_checkint(l, 3);

    } else {
        create = NGX_FILE_CREATE_OR_OPEN;
    }

    if (n >= 4) {
        access = luaL_checkint(l, 4);

    } else {
        access = NGX_FILE_DEFAULT_ACCESS;
    }

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
        goto failed;
    }

    *ctx = ngx_pcalloc(pool, sizeof(ngx_lua_file_ctx_t));
    if (*ctx == NULL) {
        ngx_destroy_pool(pool);
        errstr = "ngx_pcalloc() failed";
        goto failed;
    }

    (*ctx)->pool = pool;

    file = &(*ctx)->file;

    file->fd = ngx_open_file(name, mode, create, access);
    if (file->fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", name);
        errstr = ngx_open_file_n " failed";
        goto failed;
    }

    file->log = ngx_cycle->log;

    return 1;

failed:

    lua_pop(l, 1);
    lua_pushnil(l);
    lua_pushstring(l, errstr);

    return 2;
}


static int
ngx_lua_file_close(lua_State *l)
{
    ngx_lua_file_ctx_t  *ctx;

    ctx = ngx_lua_file(l);

    if (ctx->file.fd != NGX_INVALID_FILE) {
        ngx_close_file(ctx->file.fd);
    }

    ctx->file.fd = NGX_INVALID_FILE;

    return 0;
}


static int
ngx_lua_file_read(lua_State *l)
{
    size_t               size;
    ssize_t              n;
    ngx_buf_t           *b;
    ngx_file_t          *file;
    ngx_file_info_t      fi;
    ngx_lua_file_ctx_t  *ctx;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    ctx = ngx_lua_file(l);

    file = &ctx->file;

    if (file->fd == NGX_INVALID_FILE) {
        lua_pushnumber(l, NGX_ERROR);
        lua_pushstring(l, "invalid fd");
        return 2;
    }

    n = lua_gettop(l);

    if (n >= 3) {
        file->offset = luaL_checkint(l, 3);
    }

    if (n >= 2) {
        size = luaL_checkint(l, 2);

    } else {

        ngx_memzero(&fi, sizeof(ngx_file_info_t));

        if (ngx_fd_info(ctx->file.fd, &fi) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_fd_info_n " failed");
            lua_pushnumber(l, NGX_FILE_ERROR);
            lua_pushstring(l, "ngx_fd_info() failed");
            return 2;
        }

        size = (size_t) (ngx_file_size(&fi) - file->offset);
    }

    if (size <= 0) {
        lua_pushnumber(l, NGX_FILE_ERROR);
        lua_pushstring(l, "invalid size or the file is empty");
        return 2;
    }

    b = ctx->in;

    if (b == NULL || (size_t) (b->end - b->start) < size) {
        if (b != NULL) {
            ngx_pfree(ctx->pool, b->start);
        }

        b = ngx_create_temp_buf(ctx->pool, ngx_max(ngx_pagesize, size));
        if (b == NULL) {
            lua_pushnumber(l, NGX_ERROR);
            lua_pushstring(l, "ngx_create_temp_buf() failed");
            return 2;
        }

        ctx->in = b;
    }

    b->last = b->pos;

    n = ngx_file_aio_read(file, b->last, size, file->offset, ctx->pool);

    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      "ngx_file_aio_read() failed");
        lua_pushnumber(l, NGX_ERROR);
        lua_pushstring(l, "ngx_file_aio_read() failed");
        return 2;
    }

    if (n == NGX_AGAIN) {
        ctx->r = r;
        ctx->file.aio->data = ctx;
        ctx->file.aio->handler = ngx_lua_file_read_handler;

        return lua_yield(l, 0);
    }

    /* TODO */

    return 0;
}


static int
ngx_lua_file_write(lua_State *l)
{
#if (NGX_WIN32)

    ssize_t              n;
    ngx_str_t            str;
    ngx_buf_t           *b;
    ngx_file_t          *file;
    ngx_lua_file_ctx_t  *ctx;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    ctx = ngx_lua_file(l);

    file = &ctx->file;

    if (file->fd == NGX_INVALID_FILE) {
        lua_pushnumber(l, NGX_ERROR);
        lua_pushstring(l, "invalid fd");
        return 2;
    }

    str.data = (u_char *) luaL_checklstring(l, 2, &str.len);

    if (lua_gettop(l) >= 3) {
        file->offset = luaL_checkint(l, 3);
    }

    b = ctx->out;

    if (b == NULL || (size_t) (b->end - b->start) < str.len) {
        if (b != NULL) {
            ngx_pfree(ctx->pool, b->start);
        }

        b = ngx_create_temp_buf(ctx->pool, ngx_max(ngx_pagesize, str.len));
        if (b == NULL) {
            lua_pushnumber(l, NGX_ERROR);
            lua_pushstring(l, "ngx_create_temp_buf() failed");
            return 2;
        }

        ctx->out = b;
    }

    b->pos = b->start;
    b->last = ngx_cpymem(b->start, str.data, str.len);

    n = ngx_file_aio_write(file, b->pos, str.len, file->offset, ctx->pool);

    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      "ngx_file_aio_write() failed");
        lua_pushnumber(l, NGX_ERROR);
        lua_pushstring(l, "ngx_file_aio_write() failed");
        return 2;
    }

    if (n == NGX_AGAIN) {
        ctx->r = r;
        ctx->file.aio->data = ctx;
        ctx->file.aio->handler = ngx_lua_file_write_handler;

        return lua_yield(l, 0);
    }

    /* TODO */

    return 0;

#else

    return luaL_error(l, "not implement on this platform");

#endif
}


static int
ngx_lua_file_size(lua_State *l)
{
    ngx_file_info_t      fi;
    ngx_lua_file_ctx_t  *ctx;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    ctx = ngx_lua_file(l);

    ngx_memzero(&fi, sizeof(ngx_file_info_t));

    if (ngx_fd_info(ctx->file.fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_fd_info_n " failed");
        lua_pushnumber(l, NGX_FILE_ERROR);
        return 1;
    }

    lua_pushnumber(l, (lua_Number) ngx_file_size(&fi));

    return 1;
}


static int
ngx_lua_file_gc(lua_State *l)
{
    ngx_lua_file_ctx_t  *ctx;

    ctx = ngx_lua_file(l);

    if (ctx->file.fd != NGX_INVALID_FILE) {
        ngx_close_file(ctx->file.fd);
    }

    ngx_destroy_pool(ctx->pool);

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
    ngx_lua_ctx_t       *lua_ctx;
    ngx_event_aio_t     *aio;
    ngx_lua_file_ctx_t  *ctx;

    aio = ev->data;
    ctx = aio->data;

    ev->complete = 0;

    lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

    /* TODO: error handling */

    lua_pushnumber(lua_ctx->l, ev->available);
    lua_pushlstring(lua_ctx->l, (char *) ctx->in->pos, ev->available);

    ctx->file.offset += ev->available;

    rc = ngx_lua_thread_run(ctx->r, lua_ctx, 2);
    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_lua_finalize(ctx->r, rc);
}


#if (NGX_WIN32)

static void
ngx_lua_file_write_handler(ngx_event_t *ev)
{
    ngx_int_t            rc;
    ngx_lua_ctx_t       *lua_ctx;
    ngx_event_aio_t     *aio;
    ngx_lua_file_ctx_t  *ctx;

    aio = ev->data;
    ctx = aio->data;

    ev->complete = 0;

    lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

    /* TODO: error handling */

    lua_pushnumber(lua_ctx->l, ev->available);

    ctx->file.offset += ev->available;

    rc = ngx_lua_thread_run(ctx->r, lua_ctx, 1);
    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_lua_finalize(ctx->r, rc);
}

#endif
