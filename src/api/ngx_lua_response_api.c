
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_http_module.h>


static ngx_int_t ngx_lua_response_module_init(ngx_cycle_t *cycle);

static int ngx_lua_response_write(lua_State *l);
static int ngx_lua_response_headers_newindex(lua_State *l);
static int ngx_lua_response_cookies_newindex(lua_State *l);
static int ngx_lua_response_newindex(lua_State *l);


static ngx_lua_const_t  ngx_lua_response_consts[] = {
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


static luaL_Reg  ngx_lua_response_methods[] = {
    { "write", ngx_lua_response_write },
    { NULL, NULL }
};


ngx_lua_module_t  ngx_lua_response_module = {
    0,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_lua_response_module_init,
    NULL,
    NULL
};


static ngx_int_t
ngx_lua_response_module_init(ngx_cycle_t *cycle)
{
    int              n;
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "lua response module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    lua_getglobal(lcf->l, "nginx");

    n = sizeof(ngx_lua_response_consts) / sizeof(ngx_lua_const_t) - 1;
    n += sizeof(ngx_lua_response_methods) / sizeof(luaL_Reg) - 1;

    lua_createtable(lcf->l, 2, n);

    for (n = 0; ngx_lua_response_consts[n].name != NULL; n++) {
        lua_pushinteger(lcf->l, ngx_lua_response_consts[n].value);
        lua_setfield(lcf->l, -2, ngx_lua_response_consts[n].name);
    }

    for (n = 0; ngx_lua_response_methods[n].name != NULL; n++) {
        lua_pushcfunction(lcf->l, ngx_lua_response_methods[n].func);
        lua_setfield(lcf->l, -2, ngx_lua_response_methods[n].name);
    }

    lua_newtable(lcf->l);
    lua_createtable(lcf->l, 0, 1);
    lua_pushcfunction(lcf->l, ngx_lua_response_headers_newindex);
    lua_setfield(lcf->l, -2, "__newindex");
    lua_setmetatable(lcf->l, -2);
    lua_setfield(lcf->l, -2, "headers");

    lua_newtable(lcf->l);
    lua_createtable(lcf->l, 0, 1);
    lua_pushcfunction(lcf->l, ngx_lua_response_cookies_newindex);
    lua_setfield(lcf->l, -2, "__newindex");
    lua_setmetatable(lcf->l, -2);
    lua_setfield(lcf->l, -2, "cookies");

    lua_createtable(lcf->l, 0, 1);
    lua_pushcfunction(lcf->l, ngx_lua_response_newindex);
    lua_setfield(lcf->l, -2, "__newindex");
    lua_setmetatable(lcf->l, -2);

    lua_setfield(lcf->l, -2, "response");

    lua_pop(lcf->l, 1);

    return NGX_OK;
}


static int
ngx_lua_response_write(lua_State *l)
{
    ngx_str_t          str;
    ngx_lua_thread_t  *thr;

    thr = ngx_lua_thread(l);

    str.data = (u_char *) luaL_checklstring(l, 1, &str.len);
    ngx_lua_output(thr, str.data, str.len);

    return 0;
}


static int
ngx_lua_response_headers_newindex(lua_State *l)
{
    /* TODO: */
    return 0;
}


static int
ngx_lua_response_cookies_newindex(lua_State *l)
{
    /* TODO: */
    return 0;
}


static int
ngx_lua_response_newindex(lua_State *l)
{
    ngx_str_t            key, value, str;
    ngx_lua_thread_t    *thr;
    ngx_lua_http_ctx_t  *ctx;

    thr = ngx_lua_thread(l);

    key.data = (u_char *) luaL_checklstring(l, 2, &key.len);
    value.data = (u_char *) luaL_checklstring(l, 3, &value.len);

    str.len = value.len;
    str.data = ngx_pstrdup(thr->pool, &value);

    /* TODO: r->headers_out.status */

    ctx = thr->ctx;

    switch (key.len) {

    case 12:

        if (ngx_strncmp(key.data, "content_type", 12) == 0) {
            ctx->r->headers_out.content_type.len = str.len;
            ctx->r->headers_out.content_type.data = str.data;
        }

        break;

    default:
        break;
    }

    return 0;
}
