
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_session.h>
#include <ngx_lua.h>


typedef struct {
    ngx_uint_t         session_mode;
    ngx_str_t          session_server;
    ngx_str_t          session_name;
    size_t             session_size;
    ngx_session_t      session;
    ngx_shm_zone_t    *session_zone;
} ngx_lua_session_conf_t;


static int ngx_lua_session_create(lua_State *l);
static int ngx_lua_session_destroy(lua_State *l);
static int ngx_lua_session_set_param(lua_State *l);
static int ngx_lua_session_get_param(lua_State *l);
static int ngx_lua_session_index(lua_State *l);
static int ngx_lua_session_newindex(lua_State *l);

static ngx_int_t ngx_lua_session_module_init(ngx_cycle_t *cycle);
static void *ngx_lua_session_create_conf(ngx_cycle_t *cycle);
static char *ngx_lua_session_init_conf(ngx_cycle_t *cycle, void *conf);
static char *ngx_lua_session(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_lua_const_t  ngx_lua_session_consts[] = {
    { NULL, 0 }
};


static luaL_Reg  ngx_lua_session_methods[] = {
    { "create", ngx_lua_session_create },
    { "destroy", ngx_lua_session_destroy },
    { "set_param", ngx_lua_session_set_param },
    { "get_param", ngx_lua_session_get_param },
    { NULL, NULL }
};


static ngx_command_t  ngx_lua_session_commands[] = {

    { ngx_string("lua_session"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE23,
      ngx_lua_session,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_lua_session_module_ctx = {
    ngx_string("session"),
    ngx_lua_session_create_conf,
    ngx_lua_session_init_conf,
};


ngx_module_t  ngx_lua_session_module = {
    NGX_MODULE_V1,
    &ngx_lua_session_module_ctx,           /* module context */
    ngx_lua_session_commands,              /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_lua_session_module_init,           /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


#if (NGX_LUA_DLL)
ngx_module_t **
ngx_lua_get_modules(void)
{
    static ngx_module_t  *modules[] = {
        &ngx_lua_session_module,
        NULL
    };

    return modules;
}
#endif


static int
ngx_lua_session_create(lua_State *l)
{
#if 0
    ngx_pool_t           *pool;
    ngx_session_ctx_t    *ctx;
    ngx_http_request_t   *r;
    ngx_lua_main_conf_t  *lmcf;

    thr = ngx_lua_thread(l);

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_session_ctx_t));

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_http_module);

    if (lmcf->session_mode == NGX_SESSION_MODE_SINGLE) {
        ngx_session_create(&lmcf->session, ctx);
    }

    /* TODO */
#endif

    return 0;
}


static int
ngx_lua_session_destroy(lua_State *l)
{
#if 0
    ngx_pool_t           *pool;
    ngx_session_ctx_t    *ctx;
    ngx_http_request_t   *r;
    ngx_lua_main_conf_t  *lmcf;

    thr = ngx_lua_thread(l);

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_session_ctx_t));

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_http_module);

    if (lmcf->session_mode == NGX_SESSION_MODE_SINGLE) {
        ngx_session_destroy(&lmcf->session, ctx);
    }

    /* TODO */
#endif

    return 0;
}


static int
ngx_lua_session_set_param(lua_State *l)
{
#if 0
    ngx_pool_t           *pool;
    ngx_session_ctx_t    *ctx;
    ngx_http_request_t   *r;
    ngx_lua_main_conf_t  *lmcf;

    thr = ngx_lua_thread(l);

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_session_ctx_t));

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_http_module);

    if (lmcf->session_mode == NGX_SESSION_MODE_SINGLE) {
        ngx_session_set_param(&lmcf->session, ctx);
    }

    /* TODO */
#endif

    return 0;
}


static int
ngx_lua_session_get_param(lua_State *l)
{
#if 0
    ngx_pool_t           *pool;
    ngx_session_ctx_t    *ctx;
    ngx_http_request_t   *r;
    ngx_lua_main_conf_t  *lmcf;

    thr = ngx_lua_thread(l);

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_session_ctx_t));

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_http_module);

    if (lmcf->session_mode == NGX_SESSION_MODE_SINGLE) {
        ngx_session_get_param(&lmcf->session, ctx);
    }

    /* TODO */
#endif

    return 0;
}


static int
ngx_lua_session_index(lua_State *l)
{
#if 0
    ngx_pool_t           *pool;
    ngx_session_ctx_t    *ctx;
    ngx_http_request_t   *r;
    ngx_lua_main_conf_t  *lmcf;

    thr = ngx_lua_thread(l);

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_session_ctx_t));

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_http_module);

    if (lmcf->session_mode == NGX_SESSION_MODE_SINGLE) {
        ngx_session_get_var(&lmcf->session, ctx);
    }

    /* TODO */
#endif

    return 0;
}


static int
ngx_lua_session_newindex(lua_State *l)
{
#if 0
    ngx_pool_t           *pool;
    ngx_lua_thread_t     *thr;
    ngx_session_ctx_t    *ctx;
    ngx_lua_main_conf_t  *lmcf;

    thr = ngx_lua_thread(l);

    pool = ngx_create_pool(ngx_pagesize, thr->log);
    if (pool == NULL) {
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_session_ctx_t));

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_http_module);

    if (lmcf->session_mode == NGX_SESSION_MODE_SINGLE) {
        ngx_session_set_var(&lmcf->session, ctx);

        ngx_session_del_var(&lmcf->session, ctx);
    }

    /* TODO */
#endif

    return 0;
}


static ngx_int_t
ngx_lua_session_module_init(ngx_cycle_t *cycle)
{
    int              n;
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "lua session module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    lua_getglobal(lcf->l, "nginx");

    n = sizeof(ngx_lua_session_consts) / sizeof(ngx_lua_const_t) - 1;
    n += sizeof(ngx_lua_session_methods) / sizeof(luaL_Reg) - 1;

    lua_createtable(lcf->l, 0, n);

    for (n = 0; ngx_lua_session_consts[n].name != NULL; n++) {
        lua_pushinteger(lcf->l, ngx_lua_session_consts[n].value);
        lua_setfield(lcf->l, -2, ngx_lua_session_consts[n].name);
    }

    for (n = 0; ngx_lua_session_methods[n].name != NULL; n++) {
        lua_pushcfunction(lcf->l, ngx_lua_session_methods[n].func);
        lua_setfield(lcf->l, -2, ngx_lua_session_methods[n].name);
    }

    lua_createtable(lcf->l, 0, 2);
    lua_pushcfunction(lcf->l, ngx_lua_session_index);
    lua_setfield(lcf->l, -2, "__index");
    lua_pushcfunction(lcf->l, ngx_lua_session_newindex);
    lua_setfield(lcf->l, -2, "__newindex");
    lua_setmetatable(lcf->l, -2);

    lua_setfield(lcf->l, -2, "session");

    lua_pop(lcf->l, 1);

    return NGX_OK;
}


static void *
ngx_lua_session_create_conf(ngx_cycle_t *cycle)
{
    ngx_lua_session_conf_t  *lscf;

    lscf = ngx_pcalloc(cycle->pool, sizeof(ngx_lua_session_conf_t));
    if (lscf == NULL) {
        return NULL;
    }

    lscf->session_mode = NGX_CONF_UNSET_UINT;

    return lscf;
}


static char *
ngx_lua_session_init_conf(ngx_cycle_t *cycle, void *conf)
{
    /* TODO */

    return NGX_CONF_OK;
}


static char *
ngx_lua_session(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_lua_session_conf_t *lscf = conf;

    ngx_str_t   *value, str;
    ngx_uint_t   i;

    if (lscf->session_mode != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "mode=", 5) == 0) {
            str.len = value[i].len - 5;
            str.data = value[i].data + 5;

            if (ngx_strncmp(str.data, "single", 6) == 0) {
                lscf->session_mode = NGX_SESSION_MODE_SINGLE;

            } else if (ngx_strncmp(str.data, "cluster", 7) == 0) {
                lscf->session_mode = NGX_SESSION_MODE_CLUSTER;

            } else {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "server=", 7) == 0) {
            lscf->session_server.len = value[i].len - 7;
            lscf->session_server.data = value[i].data + 7;
            continue;
        }

        if (ngx_strncmp(value[i].data, "name=", 5) == 0) {
            lscf->session_name.len = value[i].len - 5;
            lscf->session_name.data = value[i].data + 5;
            continue;
        }

        if (ngx_strncmp(value[i].data, "size=", 5) == 0) {
            str.len = value[i].len - 5;
            str.data = value[i].data + 5;

            lscf->session_size = ngx_parse_size(&str);
            if (lscf->session_size == (size_t) NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        goto invalid;
    }

    if (lscf->session_mode == NGX_CONF_UNSET_UINT) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the directive \"lua_session\" must be specified");
        return NGX_CONF_ERROR;
    }

    if (lscf->session_mode == NGX_SESSION_MODE_SINGLE) {
        if (lscf->session_name.data == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the directive \"lua_session\" "
                               "must be specified");
            return NGX_CONF_ERROR;
        }

        ngx_conf_init_size_value(lscf->session_size, 1024 * 1024 * 1);

        lscf->session_zone = ngx_shared_memory_add(cf, &lscf->session_name,
                                                   lscf->session_size,
                                                   &ngx_lua_module);
        if (lscf->session_zone == NULL) {
            return NGX_CONF_ERROR;
        }

        if (lscf->session_zone->data) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate lua session name \"%V\"",
                               &lscf->session_name);
            return NGX_CONF_ERROR;
        }

        lscf->session_zone->init = ngx_session_init;
        lscf->session_zone->data = &lscf->session;

    } else {
        /* TODO: cluster */
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\" in lua_session", &value[i]);

    return NGX_CONF_ERROR;
}
