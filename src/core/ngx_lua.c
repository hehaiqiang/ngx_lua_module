
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua.h>


#define NGX_LUA_KEY_THR   "ngx_lua_key_thr"
#define NGX_LUA_KEY_REF   "ngx_lua_key_ref"
#define NGX_LUA_KEY_CODE  "ngx_lua_key_code"


static void ngx_lua_aio_handler(ngx_event_t *ev);
static void ngx_lua_handler(ngx_lua_thread_t *thr);
static const char *ngx_lua_reader(lua_State *l, void *data, size_t *size);
static int ngx_lua_writer(lua_State *l, const void *buf, size_t size,
    void *data);

static int ngx_lua_panic(lua_State *l);
static void ngx_lua_set_path(lua_State *l, char *key, ngx_str_t *value);
static int ngx_lua_print(lua_State *l);


ngx_int_t
ngx_lua_create(ngx_cycle_t *cycle, ngx_lua_conf_t *lcf)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua create");

    lcf->l = luaL_newstate();
    if (lcf->l == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "luaL_newstate() failed");
        return NGX_ERROR;
    }

    lua_atpanic(lcf->l, ngx_lua_panic);
    luaL_openlibs(lcf->l);

    lua_getglobal(lcf->l, "package");

    if (!lua_istable(lcf->l, -1)) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "the table \"package\" not found");
        lua_close(lcf->l);
        return NGX_ERROR;
    }

    if (lcf->path.len > 0) {
        ngx_lua_set_path(lcf->l, "path", &lcf->path);
    }

    if (lcf->cpath.len > 0) {
        ngx_lua_set_path(lcf->l, "cpath", &lcf->cpath);
    }

    lua_pop(lcf->l, 1);

    lua_newtable(lcf->l);
    lua_setfield(lcf->l, LUA_REGISTRYINDEX, NGX_LUA_KEY_REF);

    lua_register(lcf->l, "print", ngx_lua_print);

    lua_pushnil(lcf->l);
    lua_setglobal(lcf->l, "coroutine");

    lua_createtable(lcf->l, ngx_lua_max_module, 0);
    lua_setglobal(lcf->l, NGX_LUA_TABLE);

    return NGX_OK;
}


void
ngx_lua_destroy(void *data)
{
    ngx_lua_conf_t *lcf = data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "lua destroy");

    lua_close(lcf->l);
}


ngx_int_t
ngx_lua_thread_create(ngx_lua_thread_t *thr)
{
    int              top;
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua thread create");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx, ngx_lua_module);

    top = lua_gettop(lcf->l);

    lua_getfield(lcf->l, LUA_REGISTRYINDEX, NGX_LUA_KEY_REF);

    thr->l = lua_newthread(lcf->l);
    if (thr->l == NULL) {
        ngx_log_error(NGX_LOG_ALERT, thr->log, 0, "lua_newthread() failed");
        lua_pop(lcf->l, 1);
        return NGX_ERROR;
    }

    lua_newtable(thr->l);
    lua_createtable(thr->l, 0, 1);
    lua_pushvalue(thr->l, LUA_GLOBALSINDEX);
    lua_setfield(thr->l, -2, "__index");
    lua_setmetatable(thr->l, -2);
    lua_replace(thr->l, LUA_GLOBALSINDEX);

    thr->ref = luaL_ref(lcf->l, -2);
    if (thr->ref == LUA_NOREF) {
        ngx_log_error(NGX_LOG_ALERT, thr->log, 0,
                      "luaL_ref() return LUA_NOREF");
        lua_settop(lcf->l, top);
        return NGX_ERROR;
    }

    lua_pop(lcf->l, 1);

    lua_xmove(lcf->l, thr->l, 1);

    lua_pushvalue(thr->l, LUA_GLOBALSINDEX);
    lua_setfenv(thr->l, -2);

    lua_pushvalue(thr->l, -1);
    lua_setglobal(thr->l, NGX_LUA_KEY_CODE);

    lua_pushlightuserdata(thr->l, thr);
    lua_setglobal(thr->l, NGX_LUA_KEY_THR);

    /* TODO */

    ngx_lua_debug_start(thr);

    return NGX_OK;
}


void
ngx_lua_thread_destroy(ngx_lua_thread_t *thr)
{
    lua_State       *l;
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua thread destroy");

    if (thr->file.fd != NGX_INVALID_FILE) {
        ngx_close_file(thr->file.fd);
        thr->file.fd = NGX_INVALID_FILE;
    }

    if (thr->ref == LUA_NOREF) {
        return;
    }

    /* TODO */

    ngx_lua_debug_stop(thr);

    lcf = (ngx_lua_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx, ngx_lua_module);

    lua_getfield(lcf->l, LUA_REGISTRYINDEX, NGX_LUA_KEY_REF);

    lua_rawgeti(lcf->l, -1, thr->ref);
    l = lua_tothread(lcf->l, -1);
    lua_pop(lcf->l, 1);

    if (thr->l != l) {
        return;
    }

    lua_getglobal(thr->l, NGX_LUA_KEY_CODE);
    lua_getfenv(thr->l, -1);
    lua_xmove(thr->l, lcf->l, 1);
    lua_newtable(thr->l);
    lua_setfenv(thr->l, -2);

    do {
        lua_settop(thr->l, 0);
    } while (lua_resume(thr->l, 0) == LUA_YIELD);

    lua_settop(thr->l, 0);
    lua_getglobal(thr->l, NGX_LUA_KEY_CODE);
    lua_xmove(lcf->l, thr->l, 1);
    lua_setfenv(thr->l, -2);
    lua_pop(thr->l, 1);

    luaL_unref(lcf->l, -1, thr->ref);
    lua_pop(lcf->l, 1);

    thr->ref = LUA_NOREF;
}


ngx_int_t
ngx_lua_thread_run(ngx_lua_thread_t *thr, int n)
{
    int        rc;
    ngx_str_t  str;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua thread run");

    rc = lua_resume(thr->l, n);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua_resume() rc:%d", rc);

    switch (rc) {
    case 0:
        return NGX_OK;
    case LUA_YIELD:
        lua_settop(thr->l, 0);
        return NGX_AGAIN;
    case LUA_ERRRUN:
    case LUA_ERRSYNTAX:
    case LUA_ERRMEM:
    case LUA_ERRERR:
    default:
        break;
    }

    if (lua_isstring(thr->l, -1)) {
        str.data = (u_char *) lua_tolstring(thr->l, -1, &str.len);
        ngx_lua_output(thr, str.data, str.len);

        ngx_log_error(NGX_LOG_ALERT, thr->log, 0,
                      "lua_resume() failed (%d:%V)", rc, &str);
    }

    return NGX_ERROR;
}


ngx_lua_thread_t *
ngx_lua_thread(lua_State *l)
{
    ngx_lua_thread_t  *thr;

    lua_getglobal(l, NGX_LUA_KEY_THR);
    thr = lua_touserdata(l, -1);
    lua_pop(l, 1);

    if (thr == NULL) {
        luaL_error(l, "lua thread is null");
    }

    return thr;
}


ngx_int_t
ngx_lua_check_script(ngx_lua_thread_t *thr)
{
    ngx_int_t          rc;
    ngx_file_info_t    fi;
    ngx_lua_script_t  *script;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua check script");

    script = thr->script;

    if (script->from == NGX_LUA_SCRIPT_FROM_CONF) {
        thr->size = script->code.len;
        thr->mtime = -1;

    } else {

        ngx_memzero(&fi, sizeof(ngx_file_info_t));

        rc = (ngx_int_t) ngx_file_info(thr->path.data, &fi);

        if (rc == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, thr->log, ngx_errno,
                          ngx_file_info_n " \"%V\" failed", &thr->path);
            return NGX_ERROR;
        }

        thr->size = (size_t) ngx_file_size(&fi);
        thr->mtime = ngx_file_mtime(&fi);
    }

    return NGX_OK;
}


void
ngx_lua_load_script(ngx_lua_thread_t *thr)
{
    int                mode;
    size_t             size;
    ssize_t            n;
    ngx_file_t        *file;
    ngx_lua_script_t  *script;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua load script");

    /* TODO: size */

    size = ngx_max(thr->size * 4, ngx_pagesize);

    thr->buf = ngx_create_temp_buf(thr->pool, size);
    if (thr->buf == NULL) {
        ngx_lua_finalize(thr, NGX_ERROR);
        return;
    }

    if (ngx_lua_cache_get(thr) == NGX_OK) {
        thr->cached = 1;
        ngx_lua_handler(thr);
        return;
    }

    script = thr->script;

    if (script->from == NGX_LUA_SCRIPT_FROM_CONF) {
        thr->lsp = ngx_calloc_buf(thr->pool);
        if (thr->lsp == NULL) {
            ngx_lua_finalize(thr, NGX_ERROR);
            return;
        }

        thr->lsp->pos = script->code.data;
        thr->lsp->last = script->code.data + script->code.len;

        ngx_lua_handler(thr);
        return;
    }

    thr->lsp = ngx_create_temp_buf(thr->pool, thr->size);
    if (thr->lsp == NULL) {
        ngx_lua_finalize(thr, NGX_ERROR);
        return;
    }

    file = &thr->file;
    file->log = thr->log;

    mode = NGX_FILE_RDONLY|NGX_FILE_NONBLOCK;

#if (NGX_WIN32 && NGX_HAVE_FILE_AIO)
    if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
        mode |= NGX_FILE_OVERLAPPED;
    }
#endif

    file->fd = ngx_open_file(thr->path.data, mode, NGX_FILE_OPEN,
                             NGX_FILE_DEFAULT_ACCESS);
    if (file->fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ALERT, thr->log, ngx_errno,
                      ngx_open_file_n " \"%V\" failed", &thr->path);
        ngx_lua_finalize(thr, NGX_ERROR);
        return;
    }

#if !(NGX_WIN32)
    /* TODO: ngx_file_aio_read */
    n = ngx_read_file(file, thr->lsp->pos, thr->size, 0);
#else
    n = ngx_file_aio_read(file, thr->lsp->pos, thr->size, 0, thr->pool);
#endif

    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, thr->log, ngx_errno,
                      "ngx_file_aio_read() \"%V\" failed", &thr->path);
        ngx_lua_finalize(thr, NGX_ERROR);
        return;
    }

    if (n == NGX_AGAIN) {
        file->aio->data = thr;
        file->aio->handler = ngx_lua_aio_handler;
        return;
    }

    thr->lsp->last += n;

    ngx_close_file(file->fd);
    file->fd = NGX_INVALID_FILE;

    ngx_lua_handler(thr);
}


static void
ngx_lua_aio_handler(ngx_event_t *ev)
{
    ngx_event_aio_t   *aio;
    ngx_lua_thread_t  *thr;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "lua aio handler");

    aio = ev->data;
    thr = aio->data;

    /* TODO: error handling */

    ev->complete = 0;

    thr->lsp->last += ev->available;

    ngx_close_file(thr->file.fd);
    thr->file.fd = NGX_INVALID_FILE;

    ngx_lua_handler(thr);
}


static void
ngx_lua_handler(ngx_lua_thread_t *thr)
{
    ngx_int_t        rc;
    ngx_str_t        str;
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua handler");

    thr->ctx = ngx_pcalloc(thr->pool, sizeof(void *) * ngx_lua_max_module);
    if (thr->ctx == NULL) {
        ngx_lua_finalize(thr, NGX_ERROR);
        return;
    }

    if (!thr->cached) {
        if (thr->script->parser(thr) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, thr->log, 0, "parsing error");
            ngx_lua_finalize(thr, NGX_ERROR);
            return;
        }
    }

    lcf = (ngx_lua_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx, ngx_lua_module);

    rc = lua_load(lcf->l, ngx_lua_reader, thr, (char *) thr->path.data);
    if (rc != 0) {
        if (lua_isstring(lcf->l, -1)) {
            str.data = (u_char *) lua_tolstring(lcf->l, -1, &str.len);
            ngx_lua_output(thr, str.data, str.len);

            ngx_log_error(NGX_LOG_ALERT, thr->log, 0,
                          "lua_load() failed (%d:%V)", rc, &str);
        }

        ngx_lua_finalize(thr, NGX_ERROR);
        return;
    }

    if (!thr->cached) {
        thr->buf->pos = thr->buf->start;
        thr->buf->last = thr->buf->start;

        rc = lua_dump(lcf->l, ngx_lua_writer, thr);
        if (rc != 0) {
            lua_pop(lcf->l, 1);

            ngx_log_error(NGX_LOG_ALERT, thr->log, 0, "lua_dump() rc:%d", rc);

            ngx_lua_output(thr, (u_char *) "lua_dump() failed",
                           sizeof("lua_dump() failed") - 1);

            ngx_lua_finalize(thr, NGX_ERROR);
            return;
        }

        ngx_lua_cache_set(thr);
    }

    rc = lua_pcall(lcf->l, 0, 1, 0);
    if (rc != 0) {
        if (lua_isstring(lcf->l, -1)) {
            str.data = (u_char *) lua_tolstring(lcf->l, -1, &str.len);
            ngx_lua_output(thr, str.data, str.len);

            ngx_log_error(NGX_LOG_ALERT, thr->log, 0,
                          "lua_pcall() failed (%d:%V)", rc, &str);
        }

        lua_pop(lcf->l, 1);

        ngx_lua_finalize(thr, NGX_ERROR);
        return;
    }

    if (ngx_lua_thread_create(thr) == NGX_ERROR) {
        ngx_lua_finalize(thr, NGX_ERROR);
        return;
    }

    rc = ngx_lua_thread_run(thr, 0);
    if (rc != NGX_AGAIN) {
        ngx_lua_finalize(thr, rc);
        return;
    }
}


static const char *
ngx_lua_reader(lua_State *l, void *data, size_t *size)
{
    ngx_lua_thread_t *thr = data;

    u_char     *p;
    ngx_buf_t  *b;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua reader");

    b = thr->buf;

    if (b->last - b->pos == 0) {
        *size = 0;
        return NULL;
    }

    p = b->pos;
    *size = b->last - b->pos;
    b->pos = b->last;

    return (char *) p;
}


static int
ngx_lua_writer(lua_State *l, const void *buf, size_t size, void *data)
{
    ngx_lua_thread_t *thr = data;

    ngx_buf_t  *b;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua writer");

    b = thr->buf;

    if ((size_t) (b->end - b->last) < size) {
        ngx_log_error(NGX_LOG_ALERT, thr->log, 0,
                      "ngx_lua_writer() not enough space in buffer");
        return -1;
    }

    b->last = ngx_cpymem(b->last, buf, size);

    return 0;
}


static int
ngx_lua_panic(lua_State *l)
{
    ngx_str_t          str;
    ngx_log_t         *log;
    ngx_lua_thread_t  *thr;

    lua_getglobal(l, NGX_LUA_KEY_THR);
    thr = lua_touserdata(l, -1);
    lua_pop(l, 1);

    str.data = (u_char *) lua_tolstring(l, -1, &str.len);

    if (thr != NULL) {
        log = thr->log;

        ngx_lua_output(thr, str.data, str.len);

    } else {
        log = ngx_cycle->log;
    }

    ngx_log_error(NGX_LOG_ALERT, log, 0, "%V", &str);

    return 0;
}


static void
ngx_lua_set_path(lua_State *l, char *key, ngx_str_t *value)
{
    char  *old, *new, *temp;

    lua_getfield(l, -1, key);
    old = (char *) lua_tostring(l, -1);

    lua_pushlstring(l, (char *) value->data, value->len);
    new = (char *) lua_tostring(l, -1);

    temp = (char *) luaL_gsub(l, new, ";;", ";\0;");
    luaL_gsub(l, temp, "\0", old);
    lua_remove(l, -2);

    lua_setfield(l, -4, key);

    lua_pop(l, 2);
}


static int
ngx_lua_print(lua_State *l)
{
    int                n, i;
    ngx_str_t          str;
    ngx_lua_thread_t  *thr;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua print");

    n = lua_gettop(l);

    for (i = 1; i <= n; i++) {
        str.data = (u_char *) luaL_checklstring(l, i, &str.len);

        if (ngx_lua_output(thr, str.data, str.len) == NGX_ERROR) {
            lua_pushboolean(l, 0);
            lua_pushstring(l, "ngx_lua_output() failed");
            return 2;
        }
    }

    lua_pushboolean(l, 1);

    return 1;
}
