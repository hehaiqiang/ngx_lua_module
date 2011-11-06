
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_http_module.h>


static int ngx_lua_http_variable_index(lua_State *l);

static ngx_int_t ngx_lua_http_variable_module_init(ngx_cycle_t *cycle);


ngx_module_t  ngx_lua_http_variable_module = {
    NGX_MODULE_V1,
    NULL,                                  /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_lua_http_variable_module_init,     /* init module */
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
        &ngx_lua_http_variable_module,
        NULL
    };

    return modules;
}
#endif


static int
ngx_lua_http_variable_index(lua_State *l)
{
    u_char                     *p;
    ngx_str_t                   name;
    ngx_uint_t                  key;
    ngx_lua_thread_t           *thr;
    ngx_lua_http_ctx_t         *ctx;
    ngx_http_variable_value_t  *vv;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, thr->log, 0, "lua http variable index");

    p = (u_char *) luaL_checklstring(l, -1, &name.len);

    name.data = ngx_palloc(thr->pool, name.len);
    if (name.data == NULL) {
        return luaL_error(l, "ngx_palloc() return NULL");
    }

    key = ngx_hash_strlow(name.data, p, name.len);

    ctx = thr->module_ctx;

    vv = ngx_http_get_variable(ctx->r, &name, key);
    if (vv == NULL || vv->not_found) {
        lua_pushnil(l);
        return 1;
    }

    lua_pushlstring(l, (char *) vv->data, vv->len);

    return 1;
}


static ngx_int_t
ngx_lua_http_variable_module_init(ngx_cycle_t *cycle)
{
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "lua http variable module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    lua_getglobal(lcf->l, NGX_LUA_TABLE);
    lua_getfield(lcf->l, -1, NGX_LUA_HTTP_TABLE);

    lua_newtable(lcf->l);

    lua_createtable(lcf->l, 0, 1);
    lua_pushcfunction(lcf->l, ngx_lua_http_variable_index);
    lua_setfield(lcf->l, -2, "__index");
    lua_setmetatable(lcf->l, -2);

    lua_setfield(lcf->l, -2, "variable");

    lua_pop(lcf->l, 2);

    return NGX_OK;
}
