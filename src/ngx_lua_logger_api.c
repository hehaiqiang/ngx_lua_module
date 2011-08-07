
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_module.h>


static int ngx_lua_logger_error(lua_State *l);
static int ngx_lua_logger_debug(lua_State *l);


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


void
ngx_lua_logger_api_init(lua_State *l)
{
    int  n;

    n = sizeof(ngx_lua_logger_consts) / sizeof(ngx_lua_const_t) - 1;
    n += sizeof(ngx_lua_logger_methods) / sizeof(luaL_Reg) - 1;

    lua_createtable(l, 0, n);

    for (n = 0; ngx_lua_logger_consts[n].name != NULL; n++) {
        lua_pushinteger(l, ngx_lua_logger_consts[n].value);
        lua_setfield(l, -2, ngx_lua_logger_consts[n].name);
    }

    for (n = 0; ngx_lua_logger_methods[n].name != NULL; n++) {
        lua_pushcfunction(l, ngx_lua_logger_methods[n].func);
        lua_setfield(l, -2, ngx_lua_logger_methods[n].name);
    }

    lua_setfield(l, -2, "logger");
}


static int
ngx_lua_logger_error(lua_State *l)
{
    char                *str;
    ngx_uint_t           level;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    level = luaL_checkint(l, 1);
    str = (char *) luaL_checkstring(l, 2);

    ngx_log_error(level, r->connection->log, 0, str);

    return 0;
}


static int
ngx_lua_logger_debug(lua_State *l)
{
    char                *str;
    ngx_uint_t           level;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    level = luaL_checkint(l, 1);
    str = (char *) luaL_checkstring(l, 2);

    ngx_log_debug0(level, r->connection->log, 0, str);

    return 0;
}
