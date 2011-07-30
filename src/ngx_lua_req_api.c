
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_api.h>


static luaL_Reg  ngx_lua_req_methods[] = {
    { NULL, NULL }
};


static ngx_lua_const_t  ngx_lua_req_const[] = {
    { "UNKNOWN", NGX_HTTP_UNKNOWN },
    { "GET", NGX_HTTP_GET },
    { "HEAD", NGX_HTTP_HEAD },
    { "POST", NGX_HTTP_POST },
    { "PUT", NGX_HTTP_PUT },
    { "DELETE", NGX_HTTP_DELETE },
    { "MKCOL", NGX_HTTP_MKCOL },
    { "COPY", NGX_HTTP_COPY },
    { "MOVE", NGX_HTTP_MOVE },
    { "OPTIONS", NGX_HTTP_OPTIONS },
    { "PROPFIND", NGX_HTTP_PROPFIND },
    { "PROPPATCH", NGX_HTTP_PROPPATCH },
    { "LOCK", NGX_HTTP_LOCK },
    { "UNLOCK", NGX_HTTP_UNLOCK },
    { "PATCH", NGX_HTTP_PATCH },
    { "TRACE", NGX_HTTP_TRACE },
    { NULL, 0 }
};


void
ngx_lua_req_api_init(lua_State *l)
{
    int  i, n;

    n = sizeof(ngx_lua_req_methods) / sizeof(luaL_Reg) - 1;
    n += sizeof(ngx_lua_req_const) / sizeof(ngx_lua_const_t) - 1;

    lua_createtable(l, 0, n);

    for (i = 0; ngx_lua_req_methods[i].name != NULL; i++) {
        lua_pushcfunction(l, ngx_lua_req_methods[i].func);
        lua_setfield(l, -2, ngx_lua_req_methods[i].name);
    }

    for (i = 0; ngx_lua_req_const[i].name != NULL; i++) {
        lua_pushinteger(l, ngx_lua_req_const[i].value);
        lua_setfield(l, -2, ngx_lua_req_const[i].name);
    }

    lua_setfield(l, -2, "req");
}


#if 0
static int
ngx_http_lua_request_get_body(lua_State *lua)
{
    ngx_buf_t           *buf;
    ngx_http_request_t  *r;

    lua_getallocf(lua, (void **) &r);

    if (r->request_body == NULL
        || r->request_body->temp_file != NULL
        || r->request_body->bufs == NULL)
    {
        lua_pushnil(lua);
        return 1;
    }

    buf = r->request_body->bufs->buf;
    lua_pushlstring(lua, (const char *) buf->pos, buf->last - buf->pos);

    return 1;
}


static int
ngx_http_lua_request_get_body_file(lua_State *lua)
{
    ngx_str_t           *str;
    ngx_http_request_t  *r;

    lua_getallocf(lua, (void **) &r);

    if (r->request_body == NULL || r->request_body->temp_file == NULL) {
        lua_pushnil(lua);
        return 1;
    }

    str = &r->request_body->temp_file->file.name;
    lua_pushlstring(lua, (const char *) str->data, str->len);

    return 1;
}


static int
ngx_http_lua_request_read_body(lua_State *lua)
{
    ngx_str_t            str;
    ngx_lua_ctx_t       *ctx;
    ngx_http_request_t  *r;

    str.data = (u_char *) lua_tolstring(lua, 1, &str.len);

    lua_getallocf(lua, (void **) &r);
    ctx = ngx_http_get_module_ctx(r, ngx_lua_module);

    ctx->next = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (ctx->next == NULL) {
        return 0;
    }

    ctx->next->len = str.len;
    ctx->next->data = ngx_pstrdup(r->pool, &str);

    r->request_body_in_single_buf = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 1;

    if (r->request_body_in_file_only > 0) {
        r->request_body_file_log_level = 0;
    }

    ngx_http_read_client_request_body(r, ngx_http_lua_handle_request);

    return 0;
}
#endif
