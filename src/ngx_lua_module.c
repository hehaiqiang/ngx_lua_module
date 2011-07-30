
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_module.h>


static const char *ngx_lua_reader(lua_State *lua, void *data, size_t *size);
static void ngx_lua_cleanup(void *data);

static ngx_int_t ngx_lua_init(ngx_conf_t *cf);
static void *ngx_lua_create_main_conf(ngx_conf_t *cf);
static char *ngx_lua_init_main_conf(ngx_conf_t *cf, void *conf);
static char *ngx_lua(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_lua_commands[] = {

    { ngx_string("lua"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_NOARGS,
      ngx_lua,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("lua_package_path"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_lua_main_conf_t, path),
      NULL },

    { ngx_string("lua_package_cpath"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_lua_main_conf_t, cpath),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_lua_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_lua_init,                          /* postconfiguration */

    ngx_lua_create_main_conf,              /* create main configuration */
    ngx_lua_init_main_conf,                /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_lua_module = {
    NGX_MODULE_V1,
    &ngx_lua_module_ctx,                   /* module context */
    ngx_lua_commands,                      /* module directives */
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
ngx_lua_handler(ngx_http_request_t *r)
{
    size_t                root;
    u_char               *last;
    ngx_err_t             err;
    ngx_int_t             rc;
    ngx_str_t             str;
    ngx_lua_ctx_t        *ctx;
    ngx_file_info_t       fi;
    ngx_http_cleanup_t   *cln;
    ngx_lua_main_conf_t  *lmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lua handler");

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_lua_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_lua_module);

    ctx->ref = LUA_NOREF;

    last = ngx_http_map_uri_to_path(r, &ctx->path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->path.len = last - ctx->path.data;

    rc = (ngx_int_t) ngx_file_info(ctx->path.data, &fi);

    err = ngx_errno;

    if (rc == NGX_FILE_ERROR && (err == NGX_ENOENT || err == NGX_ENOPATH)) {
        return NGX_HTTP_NOT_FOUND;
    }

    if (ngx_lua_parse(r, ctx) == NGX_ERROR) {
        ngx_lua_finalize(r, NGX_ERROR);
        return NGX_OK;
    }

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_module);

    rc = lua_load(lmcf->l, ngx_lua_reader, r, (char *) ctx->path.data);
    if (rc != 0) {
        if (lua_isstring(lmcf->l, -1)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "lua_load() \"%s\" failed (rc:%d)",
                          lua_tostring(lmcf->l, -1), rc);
        }

        ngx_lua_finalize(r, NGX_ERROR);

        return NGX_OK;
    }

    rc = lua_pcall(lmcf->l, 0, 1, 0);
    if (rc != 0) {

        /* TODO */

        if (lua_isnil(lmcf->l, -1)) {
            ngx_lua_finalize(r, NGX_ERROR);
            return NGX_OK;
        }

        if (lua_isstring(lmcf->l, -1)) {
            str.data = (u_char *) lua_tolstring(lmcf->l, -1, &str.len);
        }

        lua_pop(lmcf->l, 1);

        ngx_lua_finalize(r, NGX_ERROR);

        return NGX_OK;
    }

    if (ngx_lua_thread_new(r, ctx) == NGX_ERROR) {
        ngx_lua_finalize(r, NGX_ERROR);
        return NGX_OK;
    }

    rc = ngx_lua_thread_run(r, ctx, 0);

    /* TODO: rc */

    if (rc != NGX_AGAIN) {
        ngx_lua_thread_close(r, ctx);
        ngx_lua_finalize(r, rc);
        return NGX_OK;
    }

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln->handler = ngx_lua_cleanup;
    cln->data = r;

    r->main->count++;

    return NGX_DONE;
}


static const char *
ngx_lua_reader(lua_State *s, void *data, size_t *size)
{
    ngx_http_request_t *r = data;

    u_char         *p;
    ngx_buf_t      *b;
    ngx_lua_ctx_t  *ctx;

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


static void
ngx_lua_cleanup(void *data)
{
    ngx_http_request_t *r = data;

    ngx_lua_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_lua_module);

    ngx_lua_thread_close(r, ctx);
}


static ngx_int_t
ngx_lua_init(ngx_conf_t *cf)
{
    /* TODO */

    return NGX_OK;
}


static void *
ngx_lua_create_main_conf(ngx_conf_t *cf)
{
    ngx_lua_main_conf_t  *lmcf;

    lmcf = ngx_pcalloc(cf->pool, sizeof(ngx_lua_main_conf_t));
    if (lmcf == NULL) {
        return NULL;
    }

    return lmcf;
}


static char *
ngx_lua_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_lua_main_conf_t *lmcf = conf;

    ngx_pool_cleanup_t  *cln;

    if (ngx_lua_state_new(cf, lmcf) == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        ngx_lua_state_close(lmcf->l);
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_lua_state_close;
    cln->data = lmcf->l;

    return NGX_CONF_OK;
}


static char *
ngx_lua(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_lua_handler;

    return NGX_CONF_OK;
}
