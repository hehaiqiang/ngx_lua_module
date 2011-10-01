
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_http_module.h>


static void ngx_lua_http_init_request(ngx_http_request_t *r);
static ngx_int_t ngx_lua_http_output(ngx_lua_thread_t *thr, u_char *buf,
    size_t size);
static void ngx_lua_http_finalize(ngx_lua_thread_t *thr, ngx_int_t rc);
static void ngx_lua_http_cleanup(void *data);

static ngx_int_t ngx_lua_http_init(ngx_conf_t *cf);
static char *ngx_lua_http_lua(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_lua_http_commands[] = {

    { ngx_string("lua"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_NOARGS,
      ngx_lua_http_lua,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_lua_http_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_lua_http_init,                     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_lua_http_module = {
    NGX_MODULE_V1,
    &ngx_lua_http_module_ctx,              /* module context */
    ngx_lua_http_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_lua_http_handler(ngx_http_request_t *r)
{
    size_t               root;
    u_char              *last;
    ngx_int_t            rc;
    ngx_err_t            err;
    ngx_lua_conf_t      *lcf;
    ngx_file_info_t      fi;
    ngx_lua_thread_t    *thr;
    ngx_lua_http_ctx_t  *ctx;
    ngx_http_cleanup_t  *cln;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua http handler");

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_lua_http_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->r = r;

    thr = ngx_pcalloc(r->pool, sizeof(ngx_lua_thread_t));
    if (thr == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, thr, ngx_lua_http_module);

    lcf = (ngx_lua_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx, ngx_lua_module);

    thr->pool = r->pool;
    thr->log = r->connection->log;
    thr->file.fd = NGX_INVALID_FILE;
    thr->ref = LUA_NOREF;
    thr->ctx = ctx;
    thr->c = r->connection;
    thr->output = ngx_lua_http_output;
    thr->finalize = ngx_lua_http_finalize;

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln->handler = ngx_lua_http_cleanup;
    cln->data = thr;

    last = ngx_http_map_uri_to_path(r, &thr->path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    thr->path.len = last - thr->path.data;

    ngx_memzero(&fi, sizeof(ngx_file_info_t));

    rc = (ngx_int_t) ngx_file_info(thr->path.data, &fi);

    err = ngx_errno;

    if (rc == NGX_FILE_ERROR && (err == NGX_ENOENT || err == NGX_ENOPATH)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, err,
                      ngx_file_info_n " \"%V\" failed", &thr->path);
        return NGX_HTTP_NOT_FOUND;
    }

    thr->size = (size_t) ngx_file_size(&fi);
    thr->mtime = ngx_file_mtime(&fi);

    r->request_body_in_single_buf = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 1;

    if (r->request_body_in_file_only > 0) {
        r->request_body_file_log_level = 0;
    }

    rc = ngx_http_read_client_request_body(r, ngx_lua_http_init_request);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static void
ngx_lua_http_init_request(ngx_http_request_t *r)
{
    ngx_lua_thread_t  *thr;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua http init request");

    thr = ngx_http_get_module_ctx(r, ngx_lua_http_module);

    ngx_lua_load(thr);
}


ngx_int_t
ngx_lua_http_output(ngx_lua_thread_t *thr, u_char *buf, size_t size)
{
    size_t               n;
    ngx_buf_t           *b;
    ngx_chain_t         *cl;
    ngx_lua_http_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, thr->log, 0, "lua http output");

    ctx = thr->ctx;

    /* TODO */

    if (ctx->last == NULL
        || (size_t) (ctx->last->buf->end - ctx->last->buf->last) < size)
    {
        cl = ngx_alloc_chain_link(thr->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        n = ngx_max(size, ngx_pagesize);

        cl->buf = ngx_create_temp_buf(thr->pool, n);
        if (cl->buf == NULL) {
            return NGX_ERROR;
        }

        cl->next = NULL;

        if (ctx->last != NULL) {
            ctx->last->next = cl;
        }

        ctx->last = cl;

        if (ctx->out == NULL) {
            ctx->out = cl;
        }
    }

    b = ctx->last->buf;
    b->last = ngx_copy(b->last, buf, size);

    return NGX_OK;
}


void
ngx_lua_http_finalize(ngx_lua_thread_t *thr, ngx_int_t rc)
{
    size_t               size;
    ngx_chain_t         *cl;
    ngx_lua_http_ctx_t  *ctx;
    ngx_http_request_t  *r;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, thr->log, 0, "lua http finalize");

    ctx = thr->ctx;
    r = ctx->r;

    if (r->headers_out.content_type.len == 0) {
        ngx_str_set(&r->headers_out.content_type, "text/html");
    }

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            ngx_http_finalize_request(r, rc);
            return;
        }
    }

    size = 0;

    for (cl = ctx->out; cl != NULL; cl = cl->next) {
        size += cl->buf->last - cl->buf->pos;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = size;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    if (ctx->out != NULL && size > 0) {
        ctx->last->buf->last_buf = 1;

        rc = ngx_http_output_filter(r, ctx->out);

    } else {
        rc = ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    ngx_http_finalize_request(r, rc);
}


static void
ngx_lua_http_cleanup(void *data)
{
    ngx_lua_thread_t *thr = data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, thr->log, 0, "lua http cleanup");

    if (thr->file.fd != NGX_INVALID_FILE) {
        ngx_close_file(thr->file.fd);
    }

    ngx_lua_thread_destroy(thr);
}


static ngx_int_t
ngx_lua_http_init(ngx_conf_t *cf)
{
    /* TODO: set header and body filter */

    return NGX_OK;
}


static char *
ngx_lua_http_lua(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_lua_http_handler;

    return NGX_CONF_OK;
}
