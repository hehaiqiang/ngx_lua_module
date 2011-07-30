
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_api.h>


static luaL_Reg  ngx_lua_resp[] = {
    { NULL, NULL }
};


static ngx_lua_const_t  ngx_lua_resp_const[] = {
    { "OK", NGX_HTTP_OK },
    { "CREATED", NGX_HTTP_CREATED },
    { "ACCEPTED", NGX_HTTP_ACCEPTED },
    { "NO_CONTENT", NGX_HTTP_NO_CONTENT },
    { "PARTIAL_CONTENT", NGX_HTTP_PARTIAL_CONTENT },

    { "SPECIAL_RESPONSE", NGX_HTTP_PARTIAL_CONTENT },
    { "MOVED_PERMANENTLY", NGX_HTTP_MOVED_PERMANENTLY },
    { "MOVED_TEMPORARILY", NGX_HTTP_MOVED_TEMPORARILY },
    { "SEE_OTHER", NGX_HTTP_SEE_OTHER },
    { "NOT_MODIFIED", NGX_HTTP_NOT_MODIFIED },

    { "BAD_REQUEST", NGX_HTTP_BAD_REQUEST },
    { "UNAUTHORIZED", NGX_HTTP_UNAUTHORIZED },
    { "FORBIDDEN", NGX_HTTP_FORBIDDEN },
    { "NOT_FOUND", NGX_HTTP_NOT_FOUND },
    { "NOT_ALLOWED", NGX_HTTP_NOT_ALLOWED },
    { "REQUEST_TIME_OUT", NGX_HTTP_REQUEST_TIME_OUT },
    { "CONFLICT", NGX_HTTP_CONFLICT },
    { "LENGTH_REQUIRED", NGX_HTTP_LENGTH_REQUIRED },
    { "PRECONDITION_FAILED", NGX_HTTP_PRECONDITION_FAILED },
    { "REQUEST_ENTITY_TOO_LARGE", NGX_HTTP_REQUEST_ENTITY_TOO_LARGE },
    { "REQUEST_URI_TOO_LARGE", NGX_HTTP_REQUEST_URI_TOO_LARGE },
    { "UNSUPPORTED_MEDIA_TYPE", NGX_HTTP_UNSUPPORTED_MEDIA_TYPE },
    { "RANGE_NOT_SATISFIABLE", NGX_HTTP_RANGE_NOT_SATISFIABLE },
    { "CLOSE", NGX_HTTP_CLOSE },
    { "REQUEST_HEADER_TOO_LARGE", NGX_HTTP_REQUEST_HEADER_TOO_LARGE },
    { "HTTPS_CERT_ERROR", NGX_HTTPS_CERT_ERROR },
    { "HTTPS_NO_CERT", NGX_HTTPS_NO_CERT },
    { "HTTP_TO_HTTPS", NGX_HTTP_TO_HTTPS },
    { "CLIENT_CLOSED_REQUEST", NGX_HTTP_CLIENT_CLOSED_REQUEST },

    { "INTERNAL_SERVER_ERROR", NGX_HTTP_INTERNAL_SERVER_ERROR },
    { "NOT_IMPLEMENTED", NGX_HTTP_NOT_IMPLEMENTED },
    { "BAD_GATEWAY", NGX_HTTP_BAD_GATEWAY },
    { "SERVICE_UNAVAILABLE", NGX_HTTP_SERVICE_UNAVAILABLE },
    { "GATEWAY_TIME_OUT", NGX_HTTP_GATEWAY_TIME_OUT },
    { "INSUFFICIENT_STORAGE", NGX_HTTP_INSUFFICIENT_STORAGE },

    { NULL, 0 }
};


void
ngx_lua_resp_api_init(lua_State *l)
{
    int  i, n;

    n = sizeof(ngx_lua_resp) / sizeof(luaL_Reg) - 1;
    n += sizeof(ngx_lua_resp_const) / sizeof(ngx_lua_const_t) - 1;

    lua_createtable(l, 0, n);

    for (i = 0; ngx_lua_resp[i].name != NULL; i++) {
        lua_pushcfunction(l, ngx_lua_resp[i].func);
        lua_setfield(l, -2, ngx_lua_resp[i].name);
    }

    for (i = 0; ngx_lua_resp_const[i].name != NULL; i++) {
        lua_pushinteger(l, ngx_lua_resp_const[i].value);
        lua_setfield(l, -2, ngx_lua_resp_const[i].name);
    }

    lua_setfield(l, -2, "resp");
}


#if 0
static int
ngx_http_lua_response_set_content_type(lua_State *lua)
{
    ngx_str_t            str;
    ngx_http_request_t  *r;

    lua_getallocf(lua, (void **) &r);

    str.data = (u_char *) lua_tolstring(lua, 1, &str.len);

    r->headers_out.content_type.len = str.len;
    r->headers_out.content_type.data = ngx_pstrdup(r->pool, &str);

    return 0;
}
#endif
