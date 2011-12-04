
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_http_module.h>


typedef struct {
    ngx_flag_t          enable;
    ngx_lua_script_t    script;
} ngx_lua_http_log_loc_conf_t;


static ngx_int_t ngx_lua_http_log_output(ngx_lua_thread_t *thr, u_char *buf,
    size_t size);
static void ngx_lua_http_log_finalize(ngx_lua_thread_t *thr, ngx_int_t rc);

static void *ngx_lua_http_log_create_loc_conf(ngx_conf_t *cf);
static char *ngx_lua_http_log_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_lua_http_log_init(ngx_conf_t *cf);


static ngx_command_t  ngx_lua_http_log_commands[] = {

    { ngx_string("lua_http_log"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_lua_http_log_loc_conf_t, enable),
      NULL },

    { ngx_string("lua_http_log_script_code"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_lua_set_script_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_lua_http_log_loc_conf_t, script),
      NULL },

    { ngx_string("lua_http_log_script_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_lua_set_script_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_lua_http_log_loc_conf_t, script),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_lua_http_log_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_lua_http_log_init,                 /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_lua_http_log_create_loc_conf,      /* create location configration */
    ngx_lua_http_log_merge_loc_conf        /* merge location configration */
};


ngx_module_t  ngx_lua_http_log_module = {
    NGX_MODULE_V1,
    &ngx_lua_http_log_module_ctx,          /* module context */
    ngx_lua_http_log_commands,             /* module directives */
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
ngx_lua_http_log_handler(ngx_http_request_t *r)
{
    size_t                        root;
    u_char                       *last;
    ngx_err_t                     err;
    ngx_lua_conf_t               *lcf;
    ngx_lua_thread_t             *thr;
    ngx_lua_script_t             *script;
    ngx_lua_http_ctx_t           *ctx;
    ngx_lua_http_log_loc_conf_t  *llcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua http log handler");

    llcf = ngx_http_get_module_loc_conf(r, ngx_lua_http_log_module);

    if (!llcf->enable) {
        return NGX_OK;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_lua_http_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->r = r;

    thr = ngx_pcalloc(r->pool, sizeof(ngx_lua_thread_t));
    if (thr == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, thr, ngx_lua_http_log_module);

    lcf = (ngx_lua_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx, ngx_lua_module);

    script = &llcf->script;

    thr->pool = r->pool;
    thr->log = r->connection->log;
    thr->aio = 0;
    thr->file.fd = NGX_INVALID_FILE;
    thr->ref = LUA_NOREF;
    thr->conf = lcf->conf;
    thr->module_ctx = ctx;
    thr->c = r->connection;
    thr->script = script;
    thr->output = ngx_lua_http_log_output;
    thr->finalize = ngx_lua_http_log_finalize;

    if (script->from == NGX_LUA_SCRIPT_FROM_FILE && script->path.len == 0) {
        last = ngx_http_map_uri_to_path(r, &thr->path, &root, 0);
        if (last == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        thr->path.len = last - thr->path.data;

    } else {
        thr->path = script->path;
    }

    if (ngx_lua_check_script(thr) == NGX_ERROR) {
        err = ngx_errno;

        /* TODO: err */

        if (err == NGX_ENOENT || err == NGX_ENOPATH) {
            return NGX_HTTP_NOT_FOUND;
        }

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_lua_load_script(thr);

    ngx_lua_thread_destroy(thr, 1);

    return NGX_DONE;
}


static ngx_int_t
ngx_lua_http_log_output(ngx_lua_thread_t *thr, u_char *buf, size_t size)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua http log output");

    /* TODO */

    return NGX_OK;
}


static void
ngx_lua_http_log_finalize(ngx_lua_thread_t *thr, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua http log finalize");

    /* TODO */
}


static void *
ngx_lua_http_log_create_loc_conf(ngx_conf_t *cf)
{
    ngx_lua_http_log_loc_conf_t  *llcf;

    llcf = ngx_pcalloc(cf->pool, sizeof(ngx_lua_http_log_loc_conf_t));
    if (llcf == NULL) {
        return NULL;
    }

    llcf->enable = NGX_CONF_UNSET;

    llcf->script.from = NGX_CONF_UNSET_UINT;
    llcf->script.parser = NGX_CONF_UNSET_PTR;

    return llcf;
}


static char *
ngx_lua_http_log_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_lua_http_log_loc_conf_t *prev = parent;
    ngx_lua_http_log_loc_conf_t *conf = child;

    ngx_str_t  name;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    ngx_conf_merge_uint_value(conf->script.from, prev->script.from,
                              NGX_CONF_UNSET_UINT);
    ngx_conf_merge_str_value(conf->script.path, prev->script.path, "");
    ngx_conf_merge_str_value(conf->script.code, prev->script.code, "");
    ngx_conf_merge_ptr_value(conf->script.parser, prev->script.parser,
                             NGX_CONF_UNSET_PTR);

    if (conf->enable) {
        if (conf->script.from == NGX_CONF_UNSET_UINT) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the directive \"lua_http_log_script_code\" "
                               "or \"lua_http_log_script_file\" must be "
                               "specified");
            return NGX_CONF_ERROR;
        }

        if (conf->script.parser == NGX_CONF_UNSET_PTR) {
            ngx_str_set(&name, "default");
            conf->script.parser = ngx_lua_parser_find(cf->log, &name);
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_lua_http_log_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_lua_http_log_handler;

    return NGX_OK;
}
