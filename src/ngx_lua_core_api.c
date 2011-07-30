
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_api.h>


static luaL_Reg  ngx_lua_core_methods[] = {
    { NULL, NULL }
};


static ngx_lua_const_t  ngx_lua_core_const[] = {
    { "OK", NGX_OK },
    { "ERROR", NGX_ERROR },
    { "AGAIN", NGX_AGAIN },
    { "BUSY", NGX_BUSY },
    { "DONE", NGX_DONE },
    { "DECLINED", NGX_DECLINED },
    { "ABORT", NGX_ABORT },

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


void
ngx_lua_core_api_init(lua_State *l)
{
    int  i, n;

    n = sizeof(ngx_lua_core_methods) / sizeof(luaL_Reg) - 1;
    n += sizeof(ngx_lua_core_const) / sizeof(ngx_lua_const_t) - 1;

    lua_createtable(l, 0, n);

    for (i = 0; ngx_lua_core_methods[i].name != NULL; i++) {
        lua_pushcfunction(l, ngx_lua_core_methods[i].func);
        lua_setfield(l, -2, ngx_lua_core_methods[i].name);
    }

    for (i = 0; ngx_lua_core_const[i].name != NULL; i++) {
        lua_pushinteger(l, ngx_lua_core_const[i].value);
        lua_setfield(l, -2, ngx_lua_core_const[i].name);
    }

    lua_setfield(l, -2, "core");
}
