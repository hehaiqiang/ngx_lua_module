
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

static ngx_int_t ngx_lua_http_module_init(ngx_cycle_t *cycle);
static ngx_int_t ngx_lua_http_master_init(ngx_log_t *log);
static void ngx_lua_http_master_exit(ngx_cycle_t *cycle);
static ngx_int_t ngx_lua_http_process_init(ngx_cycle_t *cycle);
static void ngx_lua_http_process_exit(ngx_cycle_t *cycle);
static ngx_int_t ngx_lua_http_thread_init(ngx_cycle_t *cycle);
static void ngx_lua_http_thread_exit(ngx_cycle_t *cycle);

static ngx_int_t ngx_lua_http_init(ngx_conf_t *cf);
static void *ngx_lua_http_create_main_conf(ngx_conf_t *cf);
static char *ngx_lua_http_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_lua_http_create_srv_conf(ngx_conf_t *cf);
static char *ngx_lua_http_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static void *ngx_lua_http_create_loc_conf(ngx_conf_t *cf);
static char *ngx_lua_http_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_lua_http_set_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_lua_http_lua(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_lua_http_commands[] = {

    { ngx_string("lua_http"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_NOARGS,
      ngx_lua_http_lua,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("lua_http_script_code"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_lua_set_script_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_lua_http_loc_conf_t, script),
      NULL },

    { ngx_string("lua_http_script_file"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_lua_set_script_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_lua_http_loc_conf_t, script),
      NULL },

    { ngx_string("lua_http_script_parser"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_lua_set_script_parser_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_lua_http_loc_conf_t, script),
      NULL },

    { ngx_string("lua_http_set_directive"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_lua_http_set_directive,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_lua_http_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_lua_http_init,                     /* postconfiguration */

    ngx_lua_http_create_main_conf,         /* create main configuration */
    ngx_lua_http_init_main_conf,           /* init main configuration */

    ngx_lua_http_create_srv_conf,          /* create server configuration */
    ngx_lua_http_merge_srv_conf,           /* merge server configuration */

    ngx_lua_http_create_loc_conf,          /* create location configuration */
    ngx_lua_http_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_lua_http_module = {
    NGX_MODULE_V1,
    &ngx_lua_http_module_ctx,              /* module context */
    ngx_lua_http_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_lua_http_master_init,              /* init master */
    ngx_lua_http_module_init,              /* init module */
    ngx_lua_http_process_init,             /* init process */
    ngx_lua_http_thread_init,              /* init thread */
    ngx_lua_http_thread_exit,              /* exit thread */
    ngx_lua_http_process_exit,             /* exit process */
    ngx_lua_http_master_exit,              /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_uint_t  ngx_lua_http_max_module;


/* The eight fixed arguments */

static ngx_uint_t  argument_number[] = {
    NGX_CONF_NOARGS,
    NGX_CONF_TAKE1,
    NGX_CONF_TAKE2,
    NGX_CONF_TAKE3,
    NGX_CONF_TAKE4,
    NGX_CONF_TAKE5,
    NGX_CONF_TAKE6,
    NGX_CONF_TAKE7
};


static ngx_int_t
ngx_lua_http_handler(ngx_http_request_t *r)
{
    size_t                    root;
    u_char                   *last;
    ngx_int_t                 rc;
    ngx_err_t                 err;
    ngx_lua_conf_t           *lcf;
    ngx_lua_thread_t         *thr;
    ngx_lua_script_t         *script;
    ngx_lua_http_ctx_t       *ctx;
    ngx_http_cleanup_t       *cln;
    ngx_lua_http_loc_conf_t  *hlcf;

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

    hlcf = ngx_http_get_module_loc_conf(r, ngx_lua_http_module);

    script = &hlcf->script;

    thr->pool = r->pool;
    thr->log = r->connection->log;
    thr->aio = 1;
    thr->file.fd = NGX_INVALID_FILE;
    thr->ref = LUA_NOREF;
    thr->conf = lcf->conf;
    thr->module_ctx = ctx;
    thr->c = r->connection;
    thr->script = script;
    thr->output = ngx_lua_http_output;
    thr->finalize = ngx_lua_http_finalize;

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

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln->handler = ngx_lua_http_cleanup;
    cln->data = thr;

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

    ngx_lua_load_script(thr);
}


static ngx_int_t
ngx_lua_http_output(ngx_lua_thread_t *thr, u_char *buf, size_t size)
{
    size_t               n;
    ngx_buf_t           *b;
    ngx_chain_t         *cl;
    ngx_lua_http_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, thr->log, 0, "lua http output");

    ctx = thr->module_ctx;

    /* TODO */

    cl = ctx->last;

    if (cl == NULL || (size_t) (cl->buf->end - cl->buf->last) < size) {
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

    b = cl->buf;
    b->last = ngx_copy(b->last, buf, size);

    return NGX_OK;
}


static void
ngx_lua_http_finalize(ngx_lua_thread_t *thr, ngx_int_t rc)
{
    size_t               size;
    ngx_chain_t         *cl;
    ngx_lua_http_ctx_t  *ctx;
    ngx_http_request_t  *r;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, thr->log, 0, "lua http finalize");

    ctx = thr->module_ctx;
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

    ngx_lua_thread_destroy(thr, 1);
}


static ngx_int_t
ngx_lua_http_module_init(ngx_cycle_t *cycle)
{
    ngx_uint_t       m;
    ngx_module_t    *module;
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua http module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    lua_getglobal(lcf->l, NGX_LUA_TABLE);
    lua_createtable(lcf->l, ngx_lua_http_max_module, 0);
    lua_setfield(lcf->l, -2, NGX_LUA_HTTP_TABLE);
    lua_pop(lcf->l, 1);

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_HTTP_MODULE) {
            continue;
        }

        if (module->init_module == NULL) {
            continue;
        }

        if (module->init_module(cycle) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_lua_http_master_init(ngx_log_t *log)
{
    ngx_uint_t     m;
    ngx_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, 0, "lua http master init");

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_HTTP_MODULE) {
            continue;
        }

        if (module->init_master == NULL) {
            continue;
        }

        if (module->init_master(log) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_lua_http_master_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t     m;
    ngx_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua http master exit");

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_HTTP_MODULE) {
            continue;
        }

        if (module->exit_master != NULL) {
            module->exit_master(cycle);
        }
    }
}


static ngx_int_t
ngx_lua_http_process_init(ngx_cycle_t *cycle)
{
    ngx_uint_t     m;
    ngx_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua http process init");

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_HTTP_MODULE) {
            continue;
        }

        if (module->init_process == NULL) {
            continue;
        }

        if (module->init_process(cycle) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_lua_http_process_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t     m;
    ngx_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua http process exit");

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_HTTP_MODULE) {
            continue;
        }

        if (module->exit_process != NULL) {
            module->exit_process(cycle);
        }
    }
}


static ngx_int_t
ngx_lua_http_thread_init(ngx_cycle_t *cycle)
{
    ngx_uint_t     m;
    ngx_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua http thread init");

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_HTTP_MODULE) {
            continue;
        }

        if (module->init_thread == NULL) {
            continue;
        }

        if (module->init_thread(cycle) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_lua_http_thread_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t     m;
    ngx_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua http thread exit");

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_HTTP_MODULE) {
            continue;
        }

        if (module->exit_thread != NULL) {
            module->exit_thread(cycle);
        }
    }
}


static ngx_int_t
ngx_lua_http_init(ngx_conf_t *cf)
{
    /* TODO: set header and body filter */

    return NGX_OK;
}


static void *
ngx_lua_http_create_main_conf(ngx_conf_t *cf)
{
    char                      *rv;
    ngx_uint_t                 m;
    ngx_http_module_t         *module;
    ngx_lua_http_main_conf_t  *hmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cf->log, 0, "lua http create main conf");

    ngx_lua_http_max_module = 0;
    for (m = 0; m < ngx_lua_max_module; m++) {
        if (ngx_lua_modules[m]->type == NGX_HTTP_MODULE) {
            ngx_lua_modules[m]->ctx_index = ngx_lua_http_max_module++;
        }
    }

    hmcf = ngx_pcalloc(cf->pool, sizeof(ngx_lua_http_main_conf_t));
    if (hmcf == NULL) {
        return NULL;
    }

    hmcf->conf = ngx_pcalloc(cf->pool,
                             sizeof(void *) * ngx_lua_http_max_module);
    if (hmcf->conf == NULL) {
        return NULL;
    }

    for (m = 0; m < ngx_lua_max_module; m++) {
        if (ngx_lua_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_lua_modules[m]->ctx;

        if (module == NULL || module->create_main_conf == NULL) {
            continue;
        }

        rv = module->create_main_conf(cf);
        if (rv == NULL) {
            return NULL;
        }

        hmcf->conf[ngx_lua_modules[m]->ctx_index] = rv;
    }

    return hmcf;
}


static char *
ngx_lua_http_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_lua_http_main_conf_t *hmcf = conf;

    char               *rc;
    ngx_uint_t          m;
    ngx_http_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cf->log, 0, "lua http init main conf");

    for (m = 0; m < ngx_lua_max_module; m++) {
        if (ngx_lua_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_lua_modules[m]->ctx;

        if (module == NULL || module->init_main_conf == NULL) {
            continue;
        }

        rc = module->init_main_conf(cf,
                                    hmcf->conf[ngx_lua_modules[m]->ctx_index]);
        if (rc != NGX_CONF_OK) {
            return rc;
        }
    }

    return NGX_CONF_OK;
}


static void *
ngx_lua_http_create_srv_conf(ngx_conf_t *cf)
{
    void                     *rv;
    ngx_uint_t                m;
    ngx_http_module_t        *module;
    ngx_lua_http_srv_conf_t  *hscf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cf->log, 0, "lua http create srv conf");

    hscf = ngx_pcalloc(cf->pool, sizeof(ngx_lua_http_srv_conf_t));
    if (hscf == NULL) {
        return NULL;
    }

    hscf->conf = ngx_pcalloc(cf->pool,
                             sizeof(void *) * ngx_lua_http_max_module);
    if (hscf->conf == NULL) {
        return NULL;
    }

    for (m = 0; m < ngx_lua_max_module; m++) {
        if (ngx_lua_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_lua_modules[m]->ctx;

        if (module == NULL || module->create_srv_conf == NULL) {
            continue;
        }

        rv = module->create_srv_conf(cf);
        if (rv == NULL) {
            return NULL;
        }

        hscf->conf[ngx_lua_modules[m]->ctx_index] = rv;
    }

    return hscf;
}


static char *
ngx_lua_http_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_lua_http_srv_conf_t *prev = parent;
    ngx_lua_http_srv_conf_t *conf = child;

    char               *rc;
    ngx_uint_t          m;
    ngx_http_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cf->log, 0, "lua http merge srv conf");

    for (m = 0; m < ngx_lua_max_module; m++) {
        if (ngx_lua_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_lua_modules[m]->ctx;

        if (module == NULL || module->merge_srv_conf == NULL) {
            continue;
        }

        rc = module->merge_srv_conf(cf,
                                    prev->conf[ngx_lua_modules[m]->ctx_index],
                                    conf->conf[ngx_lua_modules[m]->ctx_index]);
        if (rc != NGX_CONF_OK) {
            return rc;
        }
    }

    return NGX_CONF_OK;
}


static void *
ngx_lua_http_create_loc_conf(ngx_conf_t *cf)
{
    void                     *rv;
    ngx_uint_t                m;
    ngx_http_module_t        *module;
    ngx_lua_http_loc_conf_t  *hlcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cf->log, 0, "lua http create loc conf");

    hlcf = ngx_pcalloc(cf->pool, sizeof(ngx_lua_http_loc_conf_t));
    if (hlcf == NULL) {
        return NULL;
    }

    hlcf->script.from = NGX_CONF_UNSET_UINT;
    hlcf->script.parser = NGX_CONF_UNSET_PTR;

    hlcf->conf = ngx_pcalloc(cf->pool,
                             sizeof(void *) * ngx_lua_http_max_module);
    if (hlcf->conf == NULL) {
        return NULL;
    }

    for (m = 0; m < ngx_lua_max_module; m++) {
        if (ngx_lua_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_lua_modules[m]->ctx;

        if (module == NULL || module->create_loc_conf == NULL) {
            continue;
        }

        rv = module->create_loc_conf(cf);
        if (rv == NULL) {
            return NULL;
        }

        hlcf->conf[ngx_lua_modules[m]->ctx_index] = rv;
    }

    return hlcf;
}


static char *
ngx_lua_http_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_lua_http_loc_conf_t *prev = parent;
    ngx_lua_http_loc_conf_t *conf = child;

    char               *rc;
    ngx_str_t           name;
    ngx_uint_t          m;
    ngx_http_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cf->log, 0, "lua http merge loc conf");

    ngx_conf_merge_uint_value(conf->script.from, prev->script.from,
                              NGX_LUA_SCRIPT_FROM_FILE);
    ngx_conf_merge_str_value(conf->script.path, prev->script.path, "");
    ngx_conf_merge_str_value(conf->script.code, prev->script.code, "");
    ngx_conf_merge_ptr_value(conf->script.parser, prev->script.parser,
                             NGX_CONF_UNSET_PTR);

    if (conf->script.parser == NGX_CONF_UNSET_PTR) {
        ngx_str_set(&name, "lsp");
        conf->script.parser = ngx_lua_parser_find(cf->log, &name);
    }

    for (m = 0; m < ngx_lua_max_module; m++) {
        if (ngx_lua_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_lua_modules[m]->ctx;

        if (module == NULL || module->merge_loc_conf == NULL) {
            continue;
        }

        rc = module->merge_loc_conf(cf,
                                    prev->conf[ngx_lua_modules[m]->ctx_index],
                                    conf->conf[ngx_lua_modules[m]->ctx_index]);
        if (rc != NGX_CONF_OK) {
            return rc;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_lua_http_set_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                      *rv;
    ngx_str_t                 *value, *name;
    ngx_uint_t                 m, n, multi;
    ngx_module_t              *module;
    ngx_lua_http_loc_conf_t   *hlcf;
    ngx_lua_http_srv_conf_t   *hscf;
    ngx_lua_http_main_conf_t  *hmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cf->log, 0, "lua http set directive");

    value = cf->args->elts;
    name = &value[1];
    multi = 0;

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_HTTP_MODULE) {
            continue;
        }

        cmd = module->commands;
        if (cmd == NULL) {
            continue;
        }

        for ( /* void */ ; cmd->name.len; cmd++) {

            if (name->len != cmd->name.len) {
                continue;
            }

            if (ngx_strcmp(name->data, cmd->name.data) != 0) {
                continue;
            }


            /* is the directive's location right ? */

            if (!(cmd->type & cf->cmd_type)) {
                if (cmd->type & NGX_CONF_MULTI) {
                    multi = 1;
                    continue;
                }

                goto not_allowed;
            }

            /* is the directive's argument count right ? */

            n = cf->args->nelts - 1;

            if (!(cmd->type & NGX_CONF_ANY)) {

                if (cmd->type & NGX_CONF_FLAG) {

                    if (n != 2) {
                        goto invalid;
                    }

                } else if (cmd->type & NGX_CONF_1MORE) {

                    if (n < 2) {
                        goto invalid;
                    }

                } else if (cmd->type & NGX_CONF_2MORE) {

                    if (n < 3) {
                        goto invalid;
                    }

                } else if (n > NGX_CONF_MAX_ARGS) {

                    goto invalid;

                } else if (!(cmd->type & argument_number[n - 1]))
                {
                    goto invalid;
                }
            }

            /* set up the directive's configuration context */

            conf = NULL;

            if (cmd->type & NGX_HTTP_LOC_CONF) {
                hlcf = ngx_http_conf_get_module_loc_conf(cf,
                                                         ngx_lua_http_module);
                conf = hlcf->conf[module->ctx_index];

            } else if (cmd->type & NGX_HTTP_SRV_CONF) {
                hscf = ngx_http_conf_get_module_srv_conf(cf,
                                                         ngx_lua_http_module);
                conf = hscf->conf[module->ctx_index];

            } else if (cmd->type & NGX_HTTP_MAIN_CONF) {
                hmcf = ngx_http_conf_get_module_main_conf(cf,
                                                          ngx_lua_http_module);
                conf = hmcf->conf[module->ctx_index];
            }

            cf->args->elts = value + 1;
            cf->args->nelts = n;

            rv = cmd->set(cf, cmd, conf);

            cf->args->elts = value;
            cf->args->nelts = n + 1;

            if (rv == NGX_CONF_OK || rv == NGX_CONF_ERROR) {
                return rv;
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%s\" directive %s", name->data, rv);

            return NGX_CONF_ERROR;
        }
    }

    if (multi == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown directive \"%s\"", name->data);
        return NGX_CONF_ERROR;
    }

not_allowed:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "\"%s\" directive is not allowed here", name->data);
    return NGX_CONF_ERROR;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid number of arguments in \"%s\" directive",
                       name->data);

    return NGX_CONF_ERROR;
}


static char *
ngx_lua_http_lua(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cf->log, 0, "lua http lua");

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_lua_http_handler;

    return NGX_CONF_OK;
}
