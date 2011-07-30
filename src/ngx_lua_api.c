
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_api.h>


static int ngx_lua_print(lua_State *l);


void
ngx_lua_api_init(lua_State *l)
{
    lua_pushnil(l);
    lua_setglobal(l, "coroutine");

    lua_register(l, "print", ngx_lua_print);

    lua_createtable(l, 4, 0);

    ngx_lua_core_api_init(l);
    ngx_lua_dbd_api_init(l);
    /*ngx_lua_req_api_init(l);
    ngx_lua_resp_api_init(l); */

    lua_setglobal(l, "nginx");
}


static int
ngx_lua_print(lua_State *l)
{
    ngx_str_t            str;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    str.data = (u_char *) lua_tolstring(l, 1, &str.len);
    ngx_lua_output(r, str.data, str.len);

    return 0;
}
