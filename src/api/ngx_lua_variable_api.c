
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_http_module.h>


static ngx_int_t ngx_lua_variable_module_init(ngx_cycle_t *cycle);

static int ngx_lua_variable_index(lua_State *l);


ngx_lua_module_t  ngx_lua_variable_module = {
    0,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_lua_variable_module_init,
    NULL,
    NULL
};


static ngx_int_t
ngx_lua_variable_module_init(ngx_cycle_t *cycle)
{
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "lua variable module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    lua_getglobal(lcf->l, "nginx");

    lua_newtable(lcf->l);

    lua_createtable(lcf->l, 0, 1);
    lua_pushcfunction(lcf->l, ngx_lua_variable_index);
    lua_setfield(lcf->l, -2, "__index");
    lua_setmetatable(lcf->l, -2);

    lua_setfield(lcf->l, -2, "variable");

    lua_pop(lcf->l, 1);

    return NGX_OK;
}


static int
ngx_lua_variable_index(lua_State *l)
{
    u_char                     *p;
    ngx_str_t                   name;
    ngx_uint_t                  key;
    ngx_lua_thread_t           *thr;
    ngx_lua_http_ctx_t         *ctx;
    ngx_http_variable_value_t  *vv;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, thr->log, 0, "lua variable index");

    p = (u_char *) luaL_checklstring(l, -1, &name.len);

    name.data = ngx_palloc(thr->pool, name.len);
    if (name.data == NULL) {
        return luaL_error(l, "ngx_palloc() return NULL");
    }

    key = ngx_hash_strlow(name.data, p, name.len);

    ctx = thr->ctx;

    vv = ngx_http_get_variable(ctx->r, &name, key);
    if (vv == NULL || vv->not_found) {
        lua_pushnil(l);
        return 1;
    }

    lua_pushlstring(l, (char *) vv->data, vv->len);

    return 1;
}
