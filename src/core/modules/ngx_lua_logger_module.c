
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua.h>


static int ngx_lua_logger_error(lua_State *l);
static int ngx_lua_logger_debug(lua_State *l);

static ngx_int_t ngx_lua_logger_module_init(ngx_cycle_t *cycle);


static ngx_lua_const_t  ngx_lua_logger_consts[] = {
    { "STDERR", NGX_LOG_STDERR },
    { "EMERG", NGX_LOG_EMERG },
    { "ALERT", NGX_LOG_ALERT },
    { "CRIT", NGX_LOG_CRIT },
    { "ERR", NGX_LOG_ERR },
    { "WARN", NGX_LOG_WARN },
    { "NOTICE", NGX_LOG_NOTICE },
    { "INFO", NGX_LOG_INFO },
    { "DEBUG", NGX_LOG_DEBUG },

    { "DEBUG_CORE", NGX_LOG_DEBUG_CORE },
    { "DEBUG_ALLOC", NGX_LOG_DEBUG_ALLOC },
    { "DEBUG_MUTEX", NGX_LOG_DEBUG_MUTEX },
    { "DEBUG_EVENT", NGX_LOG_DEBUG_EVENT },
    { "DEBUG_HTTP", NGX_LOG_DEBUG_HTTP },
    { "DEBUG_MAIL", NGX_LOG_DEBUG_MAIL },
    { "DEBUG_MYSQL", NGX_LOG_DEBUG_MYSQL },

    { NULL, 0 }
};


static luaL_Reg  ngx_lua_logger_methods[] = {
    { "error", ngx_lua_logger_error },
    { "debug", ngx_lua_logger_debug },
    { NULL, NULL }
};


ngx_module_t  ngx_lua_logger_module = {
    NGX_MODULE_V1,
    NULL,                                  /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_lua_logger_module_init,            /* init module */
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
        &ngx_lua_logger_module,
        NULL
    };

    return modules;
}
#endif


static int
ngx_lua_logger_error(lua_State *l)
{
    char              *str;
    ngx_uint_t         level;
    ngx_lua_thread_t  *thr;

    thr = ngx_lua_thread(l);

    level = luaL_checkint(l, 1);
    str = (char *) luaL_checkstring(l, 2);

    ngx_log_error(level, thr->log, 0, str);

    return 0;
}


static int
ngx_lua_logger_debug(lua_State *l)
{
    char              *str;
    ngx_uint_t         level;
    ngx_lua_thread_t  *thr;

    thr = ngx_lua_thread(l);

    level = luaL_checkint(l, 1);
    str = (char *) luaL_checkstring(l, 2);

    ngx_log_debug0(level, thr->log, 0, str);

    return 0;
}


static ngx_int_t
ngx_lua_logger_module_init(ngx_cycle_t *cycle)
{
    int              n;
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua logger module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    lua_getglobal(lcf->l, NGX_LUA_TABLE);

    n = sizeof(ngx_lua_logger_consts) / sizeof(ngx_lua_const_t) - 1;
    n += sizeof(ngx_lua_logger_methods) / sizeof(luaL_Reg) - 1;

    lua_createtable(lcf->l, 0, n);

    for (n = 0; ngx_lua_logger_consts[n].name != NULL; n++) {
        lua_pushinteger(lcf->l, ngx_lua_logger_consts[n].value);
        lua_setfield(lcf->l, -2, ngx_lua_logger_consts[n].name);
    }

    for (n = 0; ngx_lua_logger_methods[n].name != NULL; n++) {
        lua_pushcfunction(lcf->l, ngx_lua_logger_methods[n].func);
        lua_setfield(lcf->l, -2, ngx_lua_logger_methods[n].name);
    }

    lua_setfield(lcf->l, -2, "logger");

    lua_pop(lcf->l, 1);

    return NGX_OK;
}
