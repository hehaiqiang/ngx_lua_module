
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_module.h>


static void ngx_lua_init_request(ngx_http_request_t *r);
static void ngx_lua_handle_request(ngx_http_request_t *r, ngx_lua_ctx_t *ctx);
static void ngx_lua_aio_handler(ngx_event_t *ev);
static const char *ngx_lua_reader(lua_State *l, void *data, size_t *size);
static int ngx_lua_writer(lua_State *l, const void *buf, size_t size,
    void *data);
static void ngx_lua_cleanup(void *data);


ngx_int_t
ngx_lua_handler(ngx_http_request_t *r)
{
    size_t               root;
    u_char              *last;
    ngx_int_t            rc;
    ngx_err_t            err;
    ngx_lua_ctx_t       *ctx;
    ngx_file_info_t      fi;
    ngx_http_cleanup_t  *cln;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lua handler");

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_lua_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_lua_module);

    ctx->ref = LUA_NOREF;
    ctx->file.fd = NGX_INVALID_FILE;

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln->handler = ngx_lua_cleanup;
    cln->data = r;

    last = ngx_http_map_uri_to_path(r, &ctx->path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->path.len = last - ctx->path.data;

    ngx_memzero(&fi, sizeof(ngx_file_info_t));

    rc = (ngx_int_t) ngx_file_info(ctx->path.data, &fi);

    err = ngx_errno;

    if (rc == NGX_FILE_ERROR && (err == NGX_ENOENT || err == NGX_ENOPATH)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, err,
                      ngx_file_info_n " \"%V\" failed", &ctx->path);
        return NGX_HTTP_NOT_FOUND;
    }

    ctx->size = (size_t) ngx_file_size(&fi);
    ctx->mtime = ngx_file_mtime(&fi);

    r->request_body_in_single_buf = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 1;

    if (r->request_body_in_file_only > 0) {
        r->request_body_file_log_level = 0;
    }

    rc = ngx_http_read_client_request_body(r, ngx_lua_init_request);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static void
ngx_lua_init_request(ngx_http_request_t *r)
{
    int             mode;
    size_t          size;
    ssize_t         n;
    ngx_file_t     *file;
    ngx_lua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua init request");

    ctx = ngx_http_get_module_ctx(r, ngx_lua_module);

    /* TODO: size */

    size = ngx_max(ctx->size * 4, ngx_pagesize);

    ctx->buf = ngx_create_temp_buf(r->pool, size);
    if (ctx->buf == NULL) {
        ngx_lua_finalize(r, NGX_ERROR);
        return;
    }

    if (ngx_lua_cache_get(r, ctx) == NGX_OK) {
        ctx->cached = 1;
        ngx_lua_handle_request(r, ctx);
        return;
    }

    ctx->lsp = ngx_create_temp_buf(r->pool, ctx->size);
    if (ctx->lsp == NULL) {
        ngx_lua_finalize(r, NGX_ERROR);
        return;
    }

    file = &ctx->file;
    file->log = r->connection->log;

    mode = NGX_FILE_RDONLY|NGX_FILE_NONBLOCK;

#if (NGX_WIN32 && NGX_HAVE_FILE_AIO)
    if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
        mode |= NGX_FILE_OVERLAPPED;
    }
#endif

    file->fd = ngx_open_file(ctx->path.data, mode, NGX_FILE_OPEN,
                             NGX_FILE_DEFAULT_ACCESS);
    if (file->fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_open_file_n " \"%V\" failed", &ctx->path);
        ngx_lua_finalize(r, NGX_ERROR);
        return;
    }

    n = ngx_file_aio_read(file, ctx->lsp->pos, ctx->size, 0, r->pool);

    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      "ngx_file_aio_read() \"%V\" failed", &ctx->path);
        ngx_lua_finalize(r, NGX_ERROR);
        return;
    }

    if (n == NGX_AGAIN) {
        file->aio->data = r;
        file->aio->handler = ngx_lua_aio_handler;
        return;
    }

    ngx_close_file(file->fd);
    file->fd = NGX_INVALID_FILE;

    ctx->lsp->last += n;

    ngx_lua_handle_request(r, ctx);
}


static void
ngx_lua_handle_request(ngx_http_request_t *r, ngx_lua_ctx_t *ctx)
{
    ngx_int_t             rc;
    ngx_str_t             str;
    ngx_lua_main_conf_t  *lmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua handle request");

    if (!ctx->cached) {
        if (ngx_lua_parse(r, ctx) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "ngx_lua_parse() failed (parsing error)");
            ngx_lua_finalize(r, NGX_ERROR);
            return;
        }
    }

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_module);

    rc = lua_load(lmcf->l, ngx_lua_reader, r, (char *) ctx->path.data);
    if (rc != 0) {
        if (lua_isstring(lmcf->l, -1)) {
            str.data = (u_char *) lua_tolstring(lmcf->l, -1, &str.len);
            ngx_lua_output(r, str.data, str.len);

            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "lua_load() \"%V\" failed (rc:%d)", &str, rc);
        }

        ngx_lua_finalize(r, NGX_ERROR);
        return;
    }

    if (!ctx->cached) {
        ctx->buf->pos = ctx->buf->start;
        ctx->buf->last = ctx->buf->start;

        rc = lua_dump(lmcf->l, ngx_lua_writer, r);
        if (rc != 0) {
            lua_pop(lmcf->l, 1);

            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "lua_dump() rc:%d", rc);

            ngx_lua_output(r, (u_char *) "lua_dump() failed",
                           sizeof("lua_dump() failed") - 1);

            ngx_lua_finalize(r, NGX_ERROR);
            return;
        }

        ngx_lua_cache_set(r, ctx);
    }

    rc = lua_pcall(lmcf->l, 0, 1, 0);
    if (rc != 0) {
        if (lua_isstring(lmcf->l, -1)) {
            str.data = (u_char *) lua_tolstring(lmcf->l, -1, &str.len);
            ngx_lua_output(r, str.data, str.len);

            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "lua_pcall() \"%V\" failed (rc:%d)", &str, rc);
        }

        lua_pop(lmcf->l, 1);

        ngx_lua_finalize(r, NGX_ERROR);
        return;
    }

    if (ngx_lua_thread_create(r, ctx) == NGX_ERROR) {
        ngx_lua_finalize(r, NGX_ERROR);
        return;
    }

    rc = ngx_lua_thread_run(r, ctx, 0);
    if (rc != NGX_AGAIN) {
        ngx_lua_finalize(r, rc);
        return;
    }
}


static void
ngx_lua_aio_handler(ngx_event_t *ev)
{
    ngx_lua_ctx_t       *ctx;
    ngx_event_aio_t     *aio;
    ngx_http_request_t  *r;

    aio = ev->data;
    r = aio->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua aio handler");

    /* TODO: error handling */

    ev->complete = 0;

    ctx = ngx_http_get_module_ctx(r, ngx_lua_module);

    ctx->lsp->last += ev->available;

    ngx_close_file(ctx->file.fd);
    ctx->file.fd = NGX_INVALID_FILE;

    ngx_lua_handle_request(r, ctx);
}


static const char *
ngx_lua_reader(lua_State *l, void *data, size_t *size)
{
    ngx_http_request_t *r = data;

    u_char         *p;
    ngx_buf_t      *b;
    ngx_lua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lua reader");

    ctx = ngx_http_get_module_ctx(r, ngx_lua_module);

    b = ctx->buf;

    if (b->last - b->pos == 0) {
        *size = 0;
        return NULL;
    }

    p = b->pos;
    *size = b->last - b->pos;
    b->pos += *size;

    return (char *) p;
}


static int
ngx_lua_writer(lua_State *l, const void *buf, size_t size, void *data)
{
    ngx_http_request_t *r = data;

    ngx_buf_t      *b;
    ngx_lua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lua writer");

    ctx = ngx_http_get_module_ctx(r, ngx_lua_module);

    b = ctx->buf;

    if ((size_t) (b->end - b->last) < size) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "not enough space in buffer");
        return -1;
    }

    b->last = ngx_cpymem(b->last, buf, size);

    return 0;
}


static void
ngx_lua_cleanup(void *data)
{
    ngx_http_request_t *r = data;

    ngx_lua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lua cleanup");

    ctx = ngx_http_get_module_ctx(r, ngx_lua_module);

    if (ctx->file.fd != NGX_INVALID_FILE) {
        ngx_close_file(ctx->file.fd);
    }

    ngx_lua_thread_destroy(r, ctx);
}
