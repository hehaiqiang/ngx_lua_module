
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_module.h>


static int ngx_lua_request_headers_index(lua_State *l);
static int ngx_lua_request_cookies_index(lua_State *l);
static int ngx_lua_request_get_index(lua_State *l);
static int ngx_lua_request_post_index(lua_State *l);
static int ngx_lua_request_index(lua_State *l);

static ngx_int_t ngx_lua_request_copy_request_body(ngx_http_request_t *r,
    ngx_lua_ctx_t *ctx);
static ngx_int_t ngx_lua_request_get_posted_arg(ngx_str_t *posted,
    ngx_str_t *key, ngx_str_t *value);


static ngx_lua_const_t  ngx_lua_request_consts[] = {
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


static luaL_Reg  ngx_lua_request_methods[] = {
    { NULL, NULL }
};


void
ngx_lua_request_api_init(lua_State *l)
{
    int  i, n;

    n = sizeof(ngx_lua_request_consts) / sizeof(ngx_lua_const_t) - 1;
    n += sizeof(ngx_lua_request_methods) / sizeof(luaL_Reg) - 1;

    lua_createtable(l, 4, n);

    for (i = 0; ngx_lua_request_consts[i].name != NULL; i++) {
        lua_pushinteger(l, ngx_lua_request_consts[i].value);
        lua_setfield(l, -2, ngx_lua_request_consts[i].name);
    }

    for (i = 0; ngx_lua_request_methods[i].name != NULL; i++) {
        lua_pushcfunction(l, ngx_lua_request_methods[i].func);
        lua_setfield(l, -2, ngx_lua_request_methods[i].name);
    }

    lua_newtable(l);
    lua_createtable(l, 0, 1);
    lua_pushcfunction(l, ngx_lua_request_headers_index);
    lua_setfield(l, -2, "__index");
    lua_setmetatable(l, -2);
    lua_setfield(l, -2, "headers");

    lua_newtable(l);
    lua_createtable(l, 0, 1);
    lua_pushcfunction(l, ngx_lua_request_cookies_index);
    lua_setfield(l, -2, "__index");
    lua_setmetatable(l, -2);
    lua_setfield(l, -2, "cookies");

    lua_newtable(l);
    lua_createtable(l, 0, 1);
    lua_pushcfunction(l, ngx_lua_request_get_index);
    lua_setfield(l, -2, "__index");
    lua_setmetatable(l, -2);
    lua_setfield(l, -2, "get");

    lua_newtable(l);
    lua_createtable(l, 0, 1);
    lua_pushcfunction(l, ngx_lua_request_post_index);
    lua_setfield(l, -2, "__index");
    lua_setmetatable(l, -2);
    lua_setfield(l, -2, "post");

    lua_createtable(l, 0, 1);
    lua_pushcfunction(l, ngx_lua_request_index);
    lua_setfield(l, -2, "__index");
    lua_setmetatable(l, -2);

    lua_setfield(l, -2, "request");
}


static int
ngx_lua_request_headers_index(lua_State *l)
{
    u_char               ch;
    ngx_str_t            key;
    ngx_uint_t           i, n;
    ngx_list_part_t     *part;
    ngx_table_elt_t     *header;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    key.data = (u_char *) luaL_checklstring(l, -1, &key.len);

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        for (n = 0; n < key.len && n < header[i].key.len; n++) {
            ch = header[i].key.data[n];

            if (ch >= 'A' && ch <= 'Z') {
                ch |= 0x20;

            } else if (ch == '-') {
                ch = '_';
            }

            if (key.data[n] != ch) {
                break;
            }
        }

        if (n == key.len && n == header[i].key.len) {
            lua_pushlstring(l, (char *) header[i].value.data,
                            header[i].value.len);
            return 1;
        }
    }

    lua_pushnil(l);

    return 1;
}


static int
ngx_lua_request_cookies_index(lua_State *l)
{
    ngx_str_t            key, value;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    key.data = (u_char *) luaL_checklstring(l, -1, &key.len);

    if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &key, &value)
        == NGX_DECLINED)
    {
        lua_pushnil(l);
        return 1;
    }

    lua_pushlstring(l, (char *) value.data, value.len);

    return 1;
}


static int
ngx_lua_request_get_index(lua_State *l)
{
    ngx_str_t            key, value;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    key.data = (u_char *) luaL_checklstring(l, -1, &key.len);

    if (ngx_http_arg(r, key.data, key.len, &value) == NGX_DECLINED) {
        lua_pushnil(l);
        return 1;
    }

    lua_pushlstring(l, (char *) value.data, value.len);

    return 1;
}


static int
ngx_lua_request_post_index(lua_State *l)
{
    ngx_str_t            key, value;
    ngx_lua_ctx_t       *ctx;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    if (r->request_body == NULL) {
        lua_pushnil(l);
        return 1;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_lua_module);

    key.data = (u_char *) luaL_checklstring(l, -1, &key.len);

    switch (key.len) {

    case 12:

        if (ngx_strncmp(key.data, "request_body", 12) == 0) {
            if (ngx_lua_request_copy_request_body(r, ctx) != NGX_OK) {
                lua_pushnil(l);
                return 1;
            }

            lua_pushlstring(l, (char *) ctx->request_body.data,
                            ctx->request_body.len);
            return 1;
        }

        break;

    case 17:

        if (ngx_strncmp(key.data, "request_body_file", 17) == 0) {
            if (r->request_body->temp_file == NULL) {
                lua_pushnil(l);
                return 1;
            }

            lua_pushlstring(l,
                            (char *) r->request_body->temp_file->file.name.data,
                            r->request_body->temp_file->file.name.len);
            return 1;
        }

        break;

    default:
        break;
    }

    if (ngx_lua_request_copy_request_body(r, ctx) != NGX_OK) {
        lua_pushnil(l);
        return 1;
    }

    if (ngx_lua_request_get_posted_arg(&ctx->request_body, &key, &value)
        != NGX_OK)
    {
        lua_pushnil(l);
        return 1;
    }

    /* TODO: unescape */

    lua_pushlstring(l, (char *) value.data, value.len);

    return 1;
}


static int
ngx_lua_request_index(lua_State *l)
{
    ngx_str_t            key, value;
    ngx_time_t          *tp;
    ngx_msec_int_t       ms;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    key.data = (u_char *) luaL_checklstring(l, -1, &key.len);

    switch (key.len) {

    case 3:

        if (ngx_strncmp(key.data, "uri", 3) == 0) {
            lua_pushlstring(l, (char *) r->uri.data, r->uri.len);
            return 1;
        }

        break;

    case 4:

        if (ngx_strncmp(key.data, "args", 4) == 0) {
            lua_pushlstring(l, (char *) r->args.data, r->args.len);
            return 1;
        }

        if (r->headers_in.host != NULL && ngx_strncmp(key.data, "host", 4) == 0)
        {
            lua_pushlstring(l, (char *) r->headers_in.host->value.data,
                            r->headers_in.host->value.len);
            return 1;
        }

        break;

    case 5:

        if (ngx_strncmp(key.data, "exten", 5) == 0) {
            lua_pushlstring(l, (char *) r->exten.data, r->exten.len);
            return 1;
        }

        break;

    case 6:

        if (ngx_strncmp(key.data, "method", 6) == 0) {
            lua_pushnumber(l, r->method);
            return 1;
        }

        break;

    case 7:

        if (r->headers_in.referer != NULL
            && ngx_strncmp(key.data, "referer", 7) == 0)
        {
            lua_pushlstring(l, (char *) r->headers_in.referer->value.data,
                            r->headers_in.referer->value.len);
            return 1;
        }

        break;

    case 10:

        if (r->headers_in.user_agent != NULL
            && ngx_strncmp(key.data, "user_agent", 10) == 0)
        {
            lua_pushlstring(l, (char *) r->headers_in.user_agent->value.data,
                            r->headers_in.user_agent->value.len);
            return 1;
        }

        break;

    case 11:

        if (ngx_strncmp(key.data, "method_name", 11) == 0) {
            lua_pushlstring(l, (char *) r->method_name.data,
                            r->method_name.len);
            return 1;
        }

        break;

    case 12:

        if (ngx_strncmp(key.data, "request_time", 12) == 0) {
            tp = ngx_timeofday();
            ms = (ngx_msec_int_t)
                 ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
            ms = ngx_max(ms, 0);

            lua_pushnumber(l, ms);
            return 1;
        }

        if (ngx_strncmp(key.data, "request_line", 12) == 0) {
            lua_pushlstring(l, (char *) r->request_line.data,
                            r->request_line.len);
            return 1;
        }

        if (ngx_strncmp(key.data, "unparsed_uri", 12) == 0) {
            lua_pushlstring(l, (char *) r->unparsed_uri.data,
                            r->unparsed_uri.len);
            return 1;
        }

        break;

    case 13:

        if (ngx_strncmp(key.data, "http_protocol", 13) == 0) {
            lua_pushlstring(l, (char *) r->http_protocol.data,
                            r->http_protocol.len);
            return 1;
        }

        break;

    default:
        break;
    }

    if (ngx_http_arg(r, key.data, key.len, &value) == NGX_OK) {
        lua_pushlstring(l, (char *) value.data, value.len);
        return 1;
    }

    return ngx_lua_request_post_index(l);
}
#if 0
    ngx_table_elt_t                  *connection;
    ngx_table_elt_t                  *if_modified_since;
    ngx_table_elt_t                  *if_unmodified_since;
    ngx_table_elt_t                  *content_length;
    ngx_table_elt_t                  *content_type;
    ngx_table_elt_t                  *range;
    ngx_table_elt_t                  *if_range;
    ngx_table_elt_t                  *transfer_encoding;
    ngx_table_elt_t                  *expect;
#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                  *accept_encoding;
    ngx_table_elt_t                  *via;
#endif
    ngx_table_elt_t                  *authorization;
    ngx_table_elt_t                  *keep_alive;
#if (NGX_HTTP_PROXY || NGX_HTTP_REALIP || NGX_HTTP_GEO)
    ngx_table_elt_t                  *x_forwarded_for;
#endif
#if (NGX_HTTP_REALIP)
    ngx_table_elt_t                  *x_real_ip;
#endif
#if (NGX_HTTP_HEADERS)
    ngx_table_elt_t                  *accept;
    ngx_table_elt_t                  *accept_language;
#endif
#if (NGX_HTTP_DAV)
    ngx_table_elt_t                  *date;
#endif
    ngx_str_t                         user;
    ngx_str_t                         passwd;
    ngx_str_t                         server;
    off_t                             content_length_n;
    time_t                            keep_alive_n;
    unsigned                          msie:1;
    unsigned                          msie4:1;
    unsigned                          msie6:1;
    unsigned                          opera:1;
    unsigned                          gecko:1;
    unsigned                          chrome:1;
    unsigned                          safari:1;
    unsigned                          konqueror:1;
#endif


static ngx_int_t
ngx_lua_request_copy_request_body(ngx_http_request_t *r, ngx_lua_ctx_t *ctx)
{
    u_char       *p;
    size_t        len;
    ngx_buf_t    *buf, *next;
    ngx_chain_t  *cl;

    if (r->request_body->bufs == NULL && r->request_body->temp_file == NULL) {
        return NGX_DECLINED;
    }

    if (ctx->request_body.len) {
        return NGX_OK;
    }

    if (r->request_body->bufs != NULL) {
        cl = r->request_body->bufs;
        buf = cl->buf;

        if (cl->next == NULL) {
            ctx->request_body.len = buf->last - buf->pos;
            ctx->request_body.data = buf->pos;

            return NGX_OK;
        }

        next = cl->next->buf;
        len = (buf->last - buf->pos) + (next->last - next->pos);

        p = ngx_pnalloc(r->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        p = ngx_cpymem(p, buf->pos, buf->last - buf->pos);
        ngx_memcpy(p, next->pos, next->last - next->pos);

    } else {

        /*
         * r->request_body->bufs == NULL and r->request_body->temp_file != NULL
         */

        /* TODO */

        len = 0;
        p = NULL;
    }

    ctx->request_body.len = len;
    ctx->request_body.data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_lua_request_get_posted_arg(ngx_str_t *posted, ngx_str_t *key,
    ngx_str_t *value)
{
    u_char  *p, *last;

    p = posted->data;
    last = p + posted->len;

    for ( /* void */ ; p < last; p++) {

        /* we need '=' after name, so drop one char from last */

        p = ngx_strlcasestrn(p, last - 1, key->data, key->len - 1);

        if (p == NULL) {
            return NGX_DECLINED;
        }

        if ((p == posted->data || *(p - 1) == '&') && *(p + key->len) == '=') {

            value->data = p + key->len + 1;

            p = ngx_strlchr(p, last, '&');

            if (p == NULL) {
                p = posted->data + posted->len;
            }

            value->len = p - value->data;

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}
