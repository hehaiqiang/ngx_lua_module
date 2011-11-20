
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_udp_module.h>


static ngx_int_t ngx_lua_udp_init_session(ngx_udp_session_t *s);
static void ngx_lua_udp_close_session(ngx_udp_session_t *s);
static void ngx_lua_udp_process_session(ngx_udp_session_t *s);
static ngx_int_t ngx_lua_udp_output(ngx_lua_thread_t *thr, u_char *buf,
    size_t size);
static void ngx_lua_udp_finalize(ngx_lua_thread_t *thr, ngx_int_t rc);

static ngx_int_t ngx_lua_udp_module_init(ngx_cycle_t *cycle);
static ngx_int_t ngx_lua_udp_master_init(ngx_log_t *log);
static void ngx_lua_udp_master_exit(ngx_cycle_t *cycle);
static ngx_int_t ngx_lua_udp_process_init(ngx_cycle_t *cycle);
static void ngx_lua_udp_process_exit(ngx_cycle_t *cycle);
static ngx_int_t ngx_lua_udp_thread_init(ngx_cycle_t *cycle);
static void ngx_lua_udp_thread_exit(ngx_cycle_t *cycle);

static void *ngx_lua_udp_create_main_conf(ngx_conf_t *cf);
static char *ngx_lua_udp_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_lua_udp_create_srv_conf(ngx_conf_t *cf);
static char *ngx_lua_udp_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_lua_udp_set_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_udp_protocol_t  ngx_lua_udp_protocol = {
    ngx_string("lua"),
    ngx_lua_udp_init_session,
    ngx_lua_udp_close_session,
    ngx_lua_udp_process_session,
    NULL,
    NULL
};


static ngx_command_t  ngx_lua_udp_commands[] = {

    { ngx_string("lua_udp_script_code"),
      NGX_UDP_MAIN_CONF|NGX_UDP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_lua_set_script_slot,
      NGX_UDP_SRV_CONF_OFFSET,
      offsetof(ngx_lua_udp_srv_conf_t, script),
      NULL },

    { ngx_string("lua_udp_script_file"),
      NGX_UDP_MAIN_CONF|NGX_UDP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_lua_set_script_slot,
      NGX_UDP_SRV_CONF_OFFSET,
      offsetof(ngx_lua_udp_srv_conf_t, script),
      NULL },

    { ngx_string("lua_udp_script_parser"),
      NGX_UDP_MAIN_CONF|NGX_UDP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_lua_set_script_parser_slot,
      NGX_UDP_SRV_CONF_OFFSET,
      offsetof(ngx_lua_udp_srv_conf_t, script),
      NULL },

    { ngx_string("lua_udp_set_directive"),
      NGX_UDP_MAIN_CONF|NGX_UDP_SRV_CONF|NGX_CONF_1MORE,
      ngx_lua_udp_set_directive,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_udp_module_t  ngx_lua_udp_module_ctx = {
    &ngx_lua_udp_protocol,                 /* protocol */

    ngx_lua_udp_create_main_conf,          /* create main configuration */
    ngx_lua_udp_init_main_conf,            /* init main configuration */

    ngx_lua_udp_create_srv_conf,           /* create server configuration */
    ngx_lua_udp_merge_srv_conf             /* merge server configuration */
};


ngx_module_t  ngx_lua_udp_module = {
    NGX_MODULE_V1,
    &ngx_lua_udp_module_ctx,               /* module context */
    ngx_lua_udp_commands,                  /* module directives */
    NGX_UDP_MODULE,                        /* module type */
    ngx_lua_udp_master_init,               /* init master */
    ngx_lua_udp_module_init,               /* init module */
    ngx_lua_udp_process_init,              /* init process */
    ngx_lua_udp_thread_init,               /* init thread */
    ngx_lua_udp_thread_exit,               /* exit thread */
    ngx_lua_udp_process_exit,              /* exit process */
    ngx_lua_udp_master_exit,               /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_uint_t  ngx_lua_udp_max_module;


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
ngx_lua_udp_init_session(ngx_udp_session_t *s)
{
    ngx_lua_conf_t          *lcf;
    ngx_lua_thread_t        *thr;
    ngx_lua_udp_ctx_t       *ctx;
    ngx_lua_udp_srv_conf_t  *uscf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, s->connection->log, 0,
                   "lua udp init session");

    ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_lua_udp_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->s = s;

    thr = ngx_pcalloc(s->connection->pool, sizeof(ngx_lua_thread_t));
    if (thr == NULL) {
        return NGX_ERROR;
    }

    ngx_udp_set_ctx(s, thr, ngx_lua_udp_module);

    lcf = (ngx_lua_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx, ngx_lua_module);

    uscf = ngx_udp_get_module_srv_conf(s, ngx_lua_udp_module);

    thr->pool = s->connection->pool;
    thr->log = s->connection->log;
    thr->aio = 1;
    thr->file.fd = NGX_INVALID_FILE;
    thr->ref = LUA_NOREF;
    thr->conf = lcf->conf;
    thr->module_ctx = ctx;
    thr->c = s->connection;
    thr->script = &uscf->script;
    thr->output = ngx_lua_udp_output;
    thr->finalize = ngx_lua_udp_finalize;

    thr->path = uscf->script.path;

    if (ngx_lua_check_script(thr) == NGX_ERROR) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_lua_udp_close_session(ngx_udp_session_t *s)
{
    ngx_lua_thread_t  *thr;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, s->connection->log, 0,
                   "lua udp close session");

    thr = ngx_udp_get_module_ctx(s, ngx_lua_udp_module);

    ngx_lua_thread_destroy(thr);
}


static void
ngx_lua_udp_process_session(ngx_udp_session_t *s)
{
    ngx_lua_thread_t  *thr;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, s->connection->log, 0,
                   "lua udp process session");

    thr = ngx_udp_get_module_ctx(s, ngx_lua_udp_module);

    ngx_lua_load_script(thr);
}


static ngx_int_t
ngx_lua_udp_output(ngx_lua_thread_t *thr, u_char *buf, size_t size)
{
    size_t              n;
    ngx_buf_t          *b;
    ngx_chain_t        *cl;
    ngx_lua_udp_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua udp output");

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
ngx_lua_udp_finalize(ngx_lua_thread_t *thr, ngx_int_t rc)
{
    ngx_buf_t          *b;
    ngx_udp_session_t  *s;
    ngx_lua_udp_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua udp finalize");

    ctx = thr->module_ctx;
    s = ctx->s;

    /* TODO: sending response */

    if (ctx->out != NULL) {
        b = ctx->out->buf;

        ngx_udp_send(s->connection, b->pos, b->last - b->pos);
    }

    ngx_udp_close_connection(s->connection);
}


static ngx_int_t
ngx_lua_udp_module_init(ngx_cycle_t *cycle)
{
    ngx_uint_t       m;
    ngx_module_t    *module;
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua udp module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    lua_getglobal(lcf->l, NGX_LUA_TABLE);
    lua_createtable(lcf->l, ngx_lua_udp_max_module, 0);
    lua_setfield(lcf->l, -2, NGX_LUA_UDP_TABLE);
    lua_pop(lcf->l, 1);

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_UDP_MODULE) {
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
ngx_lua_udp_master_init(ngx_log_t *log)
{
    ngx_uint_t     m;
    ngx_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, 0, "lua udp master init");

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_UDP_MODULE) {
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
ngx_lua_udp_master_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t     m;
    ngx_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua udp master exit");

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_UDP_MODULE) {
            continue;
        }

        if (module->exit_master != NULL) {
            module->exit_master(cycle);
        }
    }
}


static ngx_int_t
ngx_lua_udp_process_init(ngx_cycle_t *cycle)
{
    ngx_uint_t     m;
    ngx_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua udp process init");

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_UDP_MODULE) {
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
ngx_lua_udp_process_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t     m;
    ngx_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua udp process exit");

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_UDP_MODULE) {
            continue;
        }

        if (module->exit_process != NULL) {
            module->exit_process(cycle);
        }
    }
}


static ngx_int_t
ngx_lua_udp_thread_init(ngx_cycle_t *cycle)
{
    ngx_uint_t     m;
    ngx_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua udp thread init");

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_UDP_MODULE) {
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
ngx_lua_udp_thread_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t     m;
    ngx_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua udp thread exit");

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_UDP_MODULE) {
            continue;
        }

        if (module->exit_thread != NULL) {
            module->exit_thread(cycle);
        }
    }
}


static void *
ngx_lua_udp_create_main_conf(ngx_conf_t *cf)
{
    void                     *rv;
    ngx_uint_t                m;
    ngx_udp_module_t         *module;
    ngx_lua_udp_main_conf_t  *umcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cf->log, 0, "lua udp create main conf");

    ngx_lua_udp_max_module = 0;
    for (m = 0; m < ngx_lua_max_module; m++) {
        if (ngx_lua_modules[m]->type == NGX_UDP_MODULE) {
            ngx_lua_modules[m]->ctx_index = ngx_lua_udp_max_module++;
        }
    }

    umcf = ngx_pcalloc(cf->pool, sizeof(ngx_lua_udp_main_conf_t));
    if (umcf == NULL) {
        return NULL;
    }

    umcf->conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_lua_udp_max_module);
    if (umcf->conf == NULL) {
        return NULL;
    }

    for (m = 0; m < ngx_lua_max_module; m++) {
        if (ngx_lua_modules[m]->type != NGX_UDP_MODULE) {
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

        umcf->conf[ngx_lua_modules[m]->ctx_index] = rv;
    }

    return umcf;
}


static char *
ngx_lua_udp_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_lua_udp_main_conf_t *umcf = conf;

    char              *rc;
    ngx_uint_t         m;
    ngx_udp_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cf->log, 0, "lua udp init main conf");

    for (m = 0; m < ngx_lua_max_module; m++) {
        if (ngx_lua_modules[m]->type != NGX_UDP_MODULE) {
            continue;
        }

        module = ngx_lua_modules[m]->ctx;

        if (module == NULL || module->init_main_conf == NULL) {
            continue;
        }

        rc = module->init_main_conf(cf,
                                    umcf->conf[ngx_lua_modules[m]->ctx_index]);
        if (rc != NGX_CONF_OK) {
            return rc;
        }
    }

    return NGX_CONF_OK;
}


static void *
ngx_lua_udp_create_srv_conf(ngx_conf_t *cf)
{
    char                    *rv;
    ngx_uint_t               m;
    ngx_udp_module_t        *module;
    ngx_lua_udp_srv_conf_t  *uscf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cf->log, 0, "lua udp create srv conf");

    uscf = ngx_pcalloc(cf->pool, sizeof(ngx_lua_udp_srv_conf_t));
    if (uscf == NULL) {
        return NULL;
    }

    uscf->script.from = NGX_CONF_UNSET_UINT;
    uscf->script.parser = NGX_CONF_UNSET_PTR;

    uscf->conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_lua_udp_max_module);
    if (uscf->conf == NULL) {
        return NULL;
    }

    for (m = 0; m < ngx_lua_max_module; m++) {
        if (ngx_lua_modules[m]->type != NGX_UDP_MODULE) {
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

        uscf->conf[ngx_lua_modules[m]->ctx_index] = rv;
    }

    return uscf;
}


static char *
ngx_lua_udp_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_lua_udp_srv_conf_t *prev = parent;
    ngx_lua_udp_srv_conf_t *conf = child;

    char              *rc;
    ngx_str_t          name;
    ngx_uint_t         m;
    ngx_udp_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cf->log, 0, "lua udp merge srv conf");

    ngx_conf_merge_uint_value(conf->script.from, prev->script.from,
                              NGX_CONF_UNSET_UINT);
    ngx_conf_merge_str_value(conf->script.path, prev->script.path, "");
    ngx_conf_merge_str_value(conf->script.code, prev->script.code, "");
    ngx_conf_merge_ptr_value(conf->script.parser, prev->script.parser,
                             NGX_CONF_UNSET_PTR);

    if (conf->script.from == NGX_CONF_UNSET_UINT) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the directive \"lua_udp_script_code\" or "
                           "\"lua_udp_script_file\" must be specified");
        return NGX_CONF_ERROR;
    }

    if (conf->script.parser == NGX_CONF_UNSET_PTR) {
        ngx_str_set(&name, "default");
        conf->script.parser = ngx_lua_parser_find(cf->log, &name);
    }

    for (m = 0; m < ngx_lua_max_module; m++) {
        if (ngx_lua_modules[m]->type != NGX_UDP_MODULE) {
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


static char *
ngx_lua_udp_set_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                     *rv;
    ngx_str_t                *value, *name;
    ngx_uint_t                m, n, multi;
    ngx_module_t             *module;
    ngx_lua_udp_srv_conf_t   *uscf;
    ngx_lua_udp_main_conf_t  *umcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cf->log, 0, "lua udp set directive");

    value = cf->args->elts;
    name = &value[1];
    multi = 0;

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_UDP_MODULE) {
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

            if (cmd->type & NGX_UDP_SRV_CONF) {
                uscf = ngx_udp_conf_get_module_srv_conf(cf, ngx_lua_udp_module);
                conf = uscf->conf[module->ctx_index];

            } else if (cmd->type & NGX_UDP_MAIN_CONF) {
                umcf = ngx_udp_conf_get_module_main_conf(cf,
                                                         ngx_lua_udp_module);
                conf = umcf->conf[module->ctx_index];
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
