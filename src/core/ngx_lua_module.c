
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_md5.h>
#include <ngx_lua.h>


#define NGX_LUA_MAX_MODULES  64


typedef ngx_module_t **(*ngx_lua_get_modules_pt)(void);


static ngx_int_t ngx_lua_module_init(ngx_cycle_t *cycle);
static ngx_int_t ngx_lua_master_init(ngx_log_t *log);
static void ngx_lua_master_exit(ngx_cycle_t *cycle);
static ngx_int_t ngx_lua_process_init(ngx_cycle_t *cycle);
static void ngx_lua_process_exit(ngx_cycle_t *cycle);
static ngx_int_t ngx_lua_thread_init(ngx_cycle_t *cycle);
static void ngx_lua_thread_exit(ngx_cycle_t *cycle);

static void *ngx_lua_create_conf(ngx_cycle_t *cycle);
static char *ngx_lua_init_conf(ngx_cycle_t *cycle, void *conf);
static char *ngx_lua_load_module(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_lua_set_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_lua_commands[] = {

    { ngx_string("lua_package_path"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_lua_conf_t, path),
      NULL },

    { ngx_string("lua_package_cpath"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_lua_conf_t, cpath),
      NULL },

    { ngx_string("lua_load_module"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_lua_load_module,
      0,
      0,
      NULL },

    { ngx_string("lua_set_directive"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_1MORE,
      ngx_lua_set_directive,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_lua_module_ctx = {
    ngx_string("lua"),
    ngx_lua_create_conf,
    ngx_lua_init_conf,
};


ngx_module_t  ngx_lua_module = {
    NGX_MODULE_V1,
    &ngx_lua_module_ctx,                   /* module context */
    ngx_lua_commands,                      /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    ngx_lua_master_init,                   /* init master */
    ngx_lua_module_init,                   /* init module */
    ngx_lua_process_init,                  /* init process */
    ngx_lua_thread_init,                   /* init thread */
    ngx_lua_thread_exit,                   /* exit thread */
    ngx_lua_process_exit,                  /* exit process */
    ngx_lua_master_exit,                   /* exit master */
    NGX_MODULE_V1_PADDING
};


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


extern ngx_module_t  ngx_lua_cache_module;
extern ngx_module_t  ngx_lua_parser_module;
extern ngx_module_t  ngx_lua_session_module;
extern ngx_module_t  ngx_lua_dahua_module;
extern ngx_module_t  ngx_lua_dbd_module;
extern ngx_module_t  ngx_lua_file_module;
extern ngx_module_t  ngx_lua_logger_module;
extern ngx_module_t  ngx_lua_smtp_module;
extern ngx_module_t  ngx_lua_socket_module;
extern ngx_module_t  ngx_lua_utils_module;
extern ngx_module_t  ngx_lua_webservice_module;
extern ngx_module_t  ngx_lua_xml_module;
extern ngx_module_t  ngx_lua_http_request_module;
extern ngx_module_t  ngx_lua_http_response_module;
extern ngx_module_t  ngx_lua_http_session_module;
extern ngx_module_t  ngx_lua_http_variable_module;


ngx_module_t  *ngx_lua_modules[NGX_LUA_MAX_MODULES] = {
    &ngx_lua_cache_module,
    &ngx_lua_parser_module,
    &ngx_lua_session_module,
#if !(NGX_LUA_DLL)
    &ngx_lua_dahua_module,
    &ngx_lua_dbd_module,
    &ngx_lua_file_module,
    &ngx_lua_logger_module,
    &ngx_lua_smtp_module,
    &ngx_lua_socket_module,
    &ngx_lua_utils_module,
    &ngx_lua_webservice_module,
    &ngx_lua_xml_module,
    &ngx_lua_http_request_module,
    &ngx_lua_http_response_module,
    &ngx_lua_http_session_module,
    &ngx_lua_http_variable_module,
#endif
    NULL
};


ngx_uint_t         ngx_lua_max_module;
static ngx_uint_t  ngx_lua_max_handle;


static ngx_int_t
ngx_lua_module_init(ngx_cycle_t *cycle)
{
    ngx_uint_t           m;
    ngx_module_t        *module;
    ngx_lua_conf_t      *lcf;
    ngx_pool_cleanup_t  *cln;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    if (ngx_lua_create(cycle, lcf) == NGX_ERROR) {
        return NGX_ERROR;
    }

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_CORE_MODULE) {
            continue;
        }

        if (module->init_module == NULL) {
            continue;
        }

        if (module->init_module(cycle) == NGX_ERROR) {
            ngx_lua_destroy(lcf);
            return NGX_ERROR;
        }
    }

    cln = ngx_pool_cleanup_add(cycle->pool, 0);
    if (cln == NULL) {
        ngx_lua_destroy(lcf);
        return NGX_ERROR;
    }

    cln->handler = ngx_lua_destroy;
    cln->data = lcf;

    return NGX_OK;
}


static ngx_int_t
ngx_lua_master_init(ngx_log_t *log)
{
    ngx_uint_t     m;
    ngx_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, 0, "lua master init");

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_CORE_MODULE) {
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
ngx_lua_master_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t     m;
    ngx_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua master exit");

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_CORE_MODULE) {
            continue;
        }

        if (module->exit_master != NULL) {
            module->exit_master(cycle);
        }
    }
}


static ngx_int_t
ngx_lua_process_init(ngx_cycle_t *cycle)
{
    ngx_uint_t     m;
    ngx_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua process init");

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_CORE_MODULE) {
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
ngx_lua_process_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t       m, h;
    ngx_module_t    *module;
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua process exit");

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_CORE_MODULE) {
            continue;
        }

        if (module->exit_process != NULL) {
            module->exit_process(cycle);
        }
    }

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    for (h = 0; h < ngx_lua_max_handle; h++) {
        if (lcf->handle[h] != NULL) {
            ngx_lua_dlclose(lcf->handle[h]);
        }
    }
}


static ngx_int_t
ngx_lua_thread_init(ngx_cycle_t *cycle)
{
    ngx_uint_t     m;
    ngx_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua thread init");

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_CORE_MODULE) {
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
ngx_lua_thread_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t     m;
    ngx_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua thread exit");

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_CORE_MODULE) {
            continue;
        }

        if (module->exit_thread != NULL) {
            module->exit_thread(cycle);
        }
    }
}


static void *
ngx_lua_create_conf(ngx_cycle_t *cycle)
{
    void               *rv;
    ngx_uint_t          m;
    ngx_lua_conf_t     *lcf;
    ngx_core_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua create conf");

    lcf = ngx_pcalloc(cycle->pool, sizeof(ngx_lua_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    lcf->handle = ngx_pcalloc(cycle->pool,
                              sizeof(void *) * NGX_LUA_MAX_MODULES);
    if (lcf->handle == NULL) {
        return NULL;
    }

    lcf->conf = ngx_pcalloc(cycle->pool, sizeof(void *) * NGX_LUA_MAX_MODULES);
    if (lcf->conf == NULL) {
        return NULL;
    }

    ngx_lua_max_module = 0;
    for (m = 0; ngx_lua_modules[m] != NULL; m++) {
        ngx_lua_modules[m]->index = ngx_lua_max_module++;
    }

    for (m = 0; m < ngx_lua_max_module; m++) {
        if (ngx_lua_modules[m]->type != NGX_CORE_MODULE) {
            continue;
        }

        module = ngx_lua_modules[m]->ctx;

        if (module == NULL || module->create_conf == NULL) {
            continue;
        }

        rv = module->create_conf(cycle);
        if (rv == NULL) {
            return NULL;
        }

        lcf->conf[ngx_lua_modules[m]->index] = rv;
    }

#if (NGX_WIN32)
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOOPENFILEERRORBOX);
#endif

    return lcf;
}


static char *
ngx_lua_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_lua_conf_t *lcf = conf;

    char               *rc;
    ngx_uint_t          m;
    ngx_core_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua init conf");

    for (m = 0; m < ngx_lua_max_module; m++) {
        if (ngx_lua_modules[m]->type != NGX_CORE_MODULE) {
            continue;
        }

        module = ngx_lua_modules[m]->ctx;

        if (module == NULL || module->init_conf == NULL) {
            continue;
        }

        rc = module->init_conf(cycle, lcf->conf[ngx_lua_modules[m]->index]);
        if (rc != NGX_CONF_OK) {
            return rc;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_lua_load_module(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_lua_conf_t *lcf = conf;

    void                     *handle, *rv;
    ngx_str_t                *value;
    ngx_module_t            **mp, *m;
    ngx_core_module_t        *module;
    ngx_lua_get_modules_pt    get;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cf->log, 0, "lua load module");

    if (ngx_lua_max_module >= NGX_LUA_MAX_MODULES
        || ngx_lua_max_handle >= NGX_LUA_MAX_MODULES)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "not allowed more modules can be loaded");
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    if (ngx_conf_full_name(cf->cycle, &value[1], 0) == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    handle = ngx_lua_dlopen((char *) value[1].data);
    if (handle == NULL) {
        ngx_conf_log_error(NGX_LOG_ALERT, cf, ngx_errno,
                           ngx_lua_dlopen_n " \"%V\" failed (%s)",
                           &value[1], ngx_lua_dlerror());
        return NGX_CONF_ERROR;
    }

    get = (ngx_lua_get_modules_pt) ngx_lua_dlsym(handle, "ngx_lua_get_modules");
    if (get == NULL) {
        ngx_conf_log_error(NGX_LOG_ALERT, cf, ngx_errno,
                           ngx_lua_dlsym_n " \"ngx_lua_get_modules\" "
                           "in \"%V\" failed",
                           &value[1]);
        ngx_lua_dlclose(handle);
        return NGX_CONF_ERROR;
    }

    mp = get();
    if (mp == NULL) {
        goto done;
    }

    for (m = *mp; m != NULL; mp++, m = *mp) {

        if (ngx_lua_max_module >= NGX_LUA_MAX_MODULES) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "not allowed more modules can be loaded");
            return NGX_CONF_ERROR;
        }

        m->index = ngx_lua_max_module;

        if (m->type != NGX_CORE_MODULE) {
            goto next;
        }

        module = m->ctx;

        if (module == NULL || module->create_conf == NULL) {
            goto next;
        }

        rv = module->create_conf(cf->cycle);
        if (rv == NULL) {
            ngx_lua_dlclose(handle);
            return NGX_CONF_ERROR;
        }

        lcf->conf[m->index] = rv;

next:

        ngx_lua_modules[ngx_lua_max_module++] = m;
    }

done:

    lcf->handle[ngx_lua_max_handle++] = handle;

    return NGX_CONF_OK;
}


static char *
ngx_lua_set_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_lua_conf_t *lcf = conf;

    char          *rv;
    ngx_str_t     *value, *name;
    ngx_uint_t     m, n, multi;
    ngx_module_t  *module;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cf->log, 0, "lua set directive");

    value = cf->args->elts;
    name = &value[1];
    multi = 0;

    for (m = 0; m < ngx_lua_max_module; m++) {
        module = ngx_lua_modules[m];

        if (module->type != NGX_CORE_MODULE) {
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

            cf->args->elts = value + 1;
            cf->args->nelts = n;

            rv = cmd->set(cf, cmd, lcf->conf[module->index]);

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


char *
ngx_lua_set_script_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char *p = conf;

    u_char            *name, result[16];
    ngx_str_t         *value, *path;
    ngx_md5_t          md5;
    ngx_lua_script_t  *script;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cf->log, 0, "lua set script slot");

    script = (ngx_lua_script_t *) (p + cmd->offset);

    if (script->from != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;
    name = cmd->name.data;

    if (ngx_strcmp(name, "lua_http_script_code") == 0
        || ngx_strcmp(name, "lua_udp_script_code") == 0)
    {
        script->from = NGX_LUA_SCRIPT_FROM_CONF;
        script->code = value[1];

        ngx_md5_init(&md5);
        ngx_md5_update(&md5, script->code.data, script->code.len);
        ngx_md5_final(result, &md5);

        path = &script->path;

        path->data = ngx_pcalloc(cf->pool, 64);
        if (path->data == NULL) {
            return NGX_CONF_ERROR;
        }

        path->len = ngx_hex_dump(path->data, result, sizeof(result))
                    - path->data;

    } else {

        script->from = NGX_LUA_SCRIPT_FROM_FILE;
        script->path = value[1];

        if (ngx_conf_full_name(cf->cycle, &script->path, 0) == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


char *
ngx_lua_set_script_parser_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char *p = conf;

    ngx_str_t         *value;
    ngx_lua_script_t  *script;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cf->log, 0,
                   "lua set script parser slot");

    script = (ngx_lua_script_t *) (p + cmd->offset);

    if (script->parser != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    script->parser = ngx_lua_parser_find(cf->log, &value[1]);
    if (script->parser == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the lua parser \"%V\" not found", &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
