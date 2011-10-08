
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua.h>
#include <ngx_lua_dlfcn.h>


#define NGX_LUA_MAX_MODULES  64


static ngx_int_t ngx_lua_module_init(ngx_cycle_t *cycle);
static ngx_int_t ngx_lua_process_init(ngx_cycle_t *cycle);
static void ngx_lua_process_exit(ngx_cycle_t *cycle);

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
    NULL,                                  /* init master */
    ngx_lua_module_init,                   /* init module */
    ngx_lua_process_init,                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_lua_process_exit,                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


extern ngx_lua_module_t  ngx_lua_cache_module;
extern ngx_lua_module_t  ngx_lua_core_module;
extern ngx_lua_module_t  ngx_lua_dahua_module;
extern ngx_lua_module_t  ngx_lua_dbd_module;
extern ngx_lua_module_t  ngx_lua_file_module;
extern ngx_lua_module_t  ngx_lua_logger_module;
extern ngx_lua_module_t  ngx_lua_request_module;
extern ngx_lua_module_t  ngx_lua_response_module;
extern ngx_lua_module_t  ngx_lua_session_module;
extern ngx_lua_module_t  ngx_lua_smtp_module;
extern ngx_lua_module_t  ngx_lua_socket_module;
extern ngx_lua_module_t  ngx_lua_variable_module;
extern ngx_lua_module_t  ngx_lua_webservice_module;
extern ngx_lua_module_t  ngx_lua_xml_module;


static ngx_lua_module_t  *ngx_lua_modules[NGX_LUA_MAX_MODULES] = {
    &ngx_lua_cache_module,
    &ngx_lua_core_module,
#if !(NGX_LUA_DLL)
    &ngx_lua_dahua_module,
    &ngx_lua_dbd_module,
    &ngx_lua_file_module,
    &ngx_lua_logger_module,
    &ngx_lua_request_module,
    &ngx_lua_response_module,
    &ngx_lua_session_module,
    &ngx_lua_smtp_module,
    &ngx_lua_socket_module,
    &ngx_lua_variable_module,
    &ngx_lua_webservice_module,
    &ngx_lua_xml_module,
#endif
    NULL
};


ngx_uint_t  ngx_lua_max_module;


static ngx_int_t
ngx_lua_module_init(ngx_cycle_t *cycle)
{
    ngx_uint_t           i;
    ngx_lua_conf_t      *lcf;
    ngx_lua_module_t    *m;
    ngx_pool_cleanup_t  *cln;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    if (ngx_lua_create(cycle, lcf) == NGX_ERROR) {
        return NGX_ERROR;
    }

    for (i = 0; ngx_lua_modules[i] != NULL; i++) {
        m = ngx_lua_modules[i];

        if (m->init_module == NULL) {
            continue;
        }

        if (m->init_module(cycle) == NGX_ERROR) {
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
ngx_lua_process_init(ngx_cycle_t *cycle)
{
    ngx_uint_t         i;
    ngx_lua_module_t  *m;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua process init");

    for (i = 0; ngx_lua_modules[i] != NULL; i++) {
        m = ngx_lua_modules[i];

        if (m->init_process == NULL) {
            continue;
        }

        if (m->init_process(cycle) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_lua_process_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t         i;
    ngx_lua_module_t  *m;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua process exit");

    for (i = 0; ngx_lua_modules[i] != NULL; i++) {
        m = ngx_lua_modules[i];

        if (m->exit_process != NULL) {
            m->exit_process(cycle);
        }

        if (m->handle != NULL) {
            ngx_lua_dlclose(m->handle);
        }
    }
}


static void *
ngx_lua_create_conf(ngx_cycle_t *cycle)
{
    void              *rv;
    ngx_uint_t         i;
    ngx_lua_conf_t    *lcf;
    ngx_lua_module_t  *m;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua create conf");

    lcf = ngx_pcalloc(cycle->pool, sizeof(ngx_lua_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    lcf->conf = ngx_pcalloc(cycle->pool, sizeof(void *) * NGX_LUA_MAX_MODULES);
    if (lcf->conf == NULL) {
        return NULL;
    }

    ngx_lua_max_module = 0;
    for (i = 0; ngx_lua_modules[i]; i++) {
        ngx_lua_modules[i]->index = ngx_lua_max_module++;
    }

    for (i = 0; ngx_lua_modules[i] != NULL; i++) {
        m = ngx_lua_modules[i];

        if (m->create_conf == NULL) {
            continue;
        }

        rv = m->create_conf(cycle);
        if (rv == NULL) {
            return NULL;
        }

        lcf->conf[m->index] = rv;
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

    char              *rc;
    ngx_uint_t         i;
    ngx_lua_module_t  *m;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua init conf");

    for (i = 0; ngx_lua_modules[i] != NULL; i++) {
        m = ngx_lua_modules[i];

        if (m->init_conf == NULL) {
            continue;
        }

        rc = m->init_conf(cycle, lcf->conf[m->index]);
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

    void              *handle, *rv;
    ngx_str_t         *value;
    ngx_lua_module_t  *m;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cf->log, 0, "lua load module");

    if (ngx_lua_max_module >= NGX_LUA_MAX_MODULES) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "not allowing more modules can be loaded");
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

    m = *((ngx_lua_module_t **) ngx_lua_dlsym(handle, "module"));
    if (m == NULL) {
        ngx_conf_log_error(NGX_LOG_ALERT, cf, ngx_errno,
                           ngx_lua_dlsym_n " \"module\" in \"%V\" failed",
                           &value[1]);
        ngx_lua_dlclose(handle);
        return NGX_CONF_ERROR;
    }

    m->index = ngx_lua_max_module;
    m->handle = handle;

    if (m->create_conf != NULL) {
        rv = m->create_conf(cf->cycle);
        if (rv == NULL) {
            ngx_lua_dlclose(handle);
            return NGX_CONF_ERROR;
        }

        lcf->conf[m->index] = rv;
    }

    ngx_lua_modules[ngx_lua_max_module++] = m;

    return NGX_CONF_OK;
}


static char *
ngx_lua_set_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_lua_conf_t *lcf = conf;

    char              *rc;
    ngx_uint_t         i;
    ngx_lua_module_t  *m;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cf->log, 0, "lua set directive");

    for (i = 0; ngx_lua_modules[i] != NULL; i++) {
        m = ngx_lua_modules[i];

        if (m->set_directive == NULL) {
            continue;
        }

        rc = m->set_directive(cf, cmd, lcf->conf[m->index]);
        if (rc != (char *) NGX_DECLINED) {
            return rc;
        }
    }

    return NGX_CONF_OK;
}
