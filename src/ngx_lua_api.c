
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_api.h>


static int ngx_lua_print(lua_State *l);


static ngx_lua_const_t  ngx_lua_consts[] = {
    { "OK", NGX_OK },
    { "ERROR", NGX_ERROR },
    { "AGAIN", NGX_AGAIN },
    { "BUSY", NGX_BUSY },
    { "DONE", NGX_DONE },
    { "DECLINED", NGX_DECLINED },
    { "ABORT", NGX_ABORT },
    { NULL, 0 }
};


void
ngx_lua_api_init(lua_State *l)
{
    int  n;

    lua_pushnil(l);
    lua_setglobal(l, "coroutine");

    lua_register(l, "print", ngx_lua_print);

    n = sizeof(ngx_lua_consts) / sizeof(ngx_lua_const_t) - 1;

    lua_createtable(l, 4, n);

    for (n = 0; ngx_lua_consts[n].name != NULL; n++) {
        lua_pushinteger(l, ngx_lua_consts[n].value);
        lua_setfield(l, -2, ngx_lua_consts[n].name);
    }

    ngx_lua_dbd_api_init(l);
    ngx_lua_log_api_init(l);
    ngx_lua_req_api_init(l);
    ngx_lua_resp_api_init(l);

    lua_setglobal(l, "nginx");
}


static int
ngx_lua_print(lua_State *l)
{
    ngx_str_t            str;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    str.data = (u_char *) luaL_checklstring(l, 1, &str.len);
    ngx_lua_output(r, str.data, str.len);

    return 0;
}
