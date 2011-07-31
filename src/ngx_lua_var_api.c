
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_api.h>


static int ngx_lua_var_index(lua_State *l);


void
ngx_lua_var_api_init(lua_State *l)
{
    lua_newtable(l);
    lua_createtable(l, 0, 1);
    lua_pushcfunction(l, ngx_lua_var_index);
    lua_setfield(l, -2, "__index");
    lua_setmetatable(l, -2);
    lua_setfield(l, -2, "var");
}


static int
ngx_lua_var_index(lua_State *l)
{
    u_char                     *p;
    ngx_str_t                   name;
    ngx_uint_t                  key;
    ngx_http_request_t         *r;
    ngx_http_variable_value_t  *vv;

    r = ngx_lua_request(l);

    p = (u_char *) luaL_checklstring(l, -1, &name.len);

    name.data = ngx_palloc(r->pool, name.len);
    if (name.data == NULL) {
        return luaL_error(l, "ngx_palloc() return NULL");
    }

    key = ngx_hash_strlow(name.data, p, name.len);

    vv = ngx_http_get_variable(r, &name, key);
    if (vv == NULL || vv->not_found) {
        lua_pushnil(l);
        return 1;
    }

    lua_pushlstring(l, (char *) vv->data, vv->len);

    return 1;
}
