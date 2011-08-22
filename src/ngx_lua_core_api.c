
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_md5.h>
#include <ngx_sha1.h>
#include <ngx_lua_module.h>


static int ngx_lua_print(lua_State *l);

static int ngx_lua_escape_uri(lua_State *l);
static int ngx_lua_unescape_uri(lua_State *l);
static int ngx_lua_encode_base64(lua_State *l);
static int ngx_lua_decode_base64(lua_State *l);

static int ngx_lua_crc16(lua_State *l);
static int ngx_lua_crc32(lua_State *l);
static int ngx_lua_murmur_hash2(lua_State *l);
static int ngx_lua_md5(lua_State *l);
static int ngx_lua_sha1(lua_State *l);


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


static luaL_Reg  ngx_lua_methods[] = {
    { "escape_uri", ngx_lua_escape_uri },
    { "unescape_uri", ngx_lua_unescape_uri },
    { "encode_base64", ngx_lua_encode_base64 },
    { "decode_base64", ngx_lua_decode_base64 },
    { "crc16", ngx_lua_crc16 },
    { "crc32", ngx_lua_crc32 },
    { "murmur_hash2", ngx_lua_murmur_hash2 },
    { "md5", ngx_lua_md5 },
    { "sha1", ngx_lua_sha1 },
    { "http", ngx_lua_http },
    { "smtp", ngx_lua_smtp },
    { NULL, NULL }
};


void
ngx_lua_api_init(lua_State *l)
{
    int  n;

    lua_pushnil(l);
    lua_setglobal(l, "coroutine");

    lua_register(l, "print", ngx_lua_print);

    n = sizeof(ngx_lua_consts) / sizeof(ngx_lua_const_t) - 1;
    n += sizeof(ngx_lua_methods) / sizeof(luaL_Reg) - 1;

    /* STUB */
    lua_createtable(l, 9, n);

    for (n = 0; ngx_lua_consts[n].name != NULL; n++) {
        lua_pushinteger(l, ngx_lua_consts[n].value);
        lua_setfield(l, -2, ngx_lua_consts[n].name);
    }

    for (n = 0; ngx_lua_methods[n].name != NULL; n++) {
        lua_pushcfunction(l, ngx_lua_methods[n].func);
        lua_setfield(l, -2, ngx_lua_methods[n].name);
    }

    ngx_lua_axis2c_api_init(l);
    ngx_lua_dbd_api_init(l);
    ngx_lua_file_api_init(l);
    ngx_lua_logger_api_init(l);
    ngx_lua_request_api_init(l);
    ngx_lua_response_api_init(l);
    ngx_lua_session_api_init(l);
    ngx_lua_socket_api_init(l);
    ngx_lua_variable_api_init(l);

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


static int
ngx_lua_escape_uri(lua_State *l)
{
    size_t               len;
    u_char              *p, *last;
    ngx_str_t            str;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    str.data = (u_char *) luaL_checklstring(l, 1, &str.len);

    len = 2 * ngx_escape_uri(NULL, str.data, str.len, 0);
    if (len == 0) {
        goto done;
    }

    p = ngx_pnalloc(r->pool, str.len + len);
    if (p == NULL) {
        return luaL_error(l, "ngx_pnalloc() failed");
    }

    last = (u_char *) ngx_escape_uri(p, str.data, str.len, 0);

    str.len = last - p;
    str.data = p;

done:

    lua_pushlstring(l, (char *) str.data, str.len);

    return 1;
}


static int
ngx_lua_unescape_uri(lua_State *l)
{
    u_char              *dst, *src;
    ngx_str_t            str;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    str.data = (u_char *) luaL_checklstring(l, 1, &str.len);

    dst = ngx_pnalloc(r->pool, str.len);
    if (dst == NULL) {
        return luaL_error(l, "ngx_pnalloc() failed");
    }

    src = str.data;

    str.data = dst;
    ngx_unescape_uri(&dst, &src, str.len, 0);
    str.len = dst - str.data;

    lua_pushlstring(l, (char *) str.data, str.len);

    return 1;
}


static int
ngx_lua_encode_base64(lua_State *l)
{
    ngx_str_t            dst, src;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    src.data = (u_char *) luaL_checklstring(l, 1, &src.len);

    dst.len = ngx_base64_encoded_length(src.len);

    dst.data = ngx_pnalloc(r->pool, dst.len);
    if (dst.data == NULL) {
        return luaL_error(l, "ngx_pnalloc() failed");
    }

    ngx_encode_base64(&dst, &src);

    lua_pushlstring(l, (char *) dst.data, dst.len);

    return 1;
}


static int
ngx_lua_decode_base64(lua_State *l)
{
    ngx_str_t            dst, src;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    src.data = (u_char *) luaL_checklstring(l, 1, &src.len);

    dst.len = ngx_base64_decoded_length(src.len);

    dst.data = ngx_pnalloc(r->pool, dst.len);
    if (dst.data == NULL) {
        return luaL_error(l, "ngx_pnalloc() failed");
    }

    if (ngx_decode_base64(&dst, &src) == NGX_ERROR) {
        return luaL_error(l, "ngx_decode_base64() failed");
    }

    lua_pushlstring(l, (char *) dst.data, dst.len);

    return 1;
}


static int
ngx_lua_crc16(lua_State *l)
{
    u_char     crc[4], hex[8], *last;
    uint32_t   crc16;
    ngx_str_t  str;

    str.data = (u_char *) luaL_checklstring(l, 1, &str.len);

    crc16 = ngx_crc(str.data, str.len);

    crc[0] = crc16 >> 24;
    crc[1] = (u_char) (crc16 >> 16);
    crc[2] = (u_char) (crc16 >> 8);
    crc[3] = (u_char) crc16;

    last = ngx_hex_dump(hex, crc, 4);

    lua_pushlstring(l, (char *) hex, last - hex);

    return 1;
}


static int
ngx_lua_crc32(lua_State *l)
{
    u_char     crc[4], hex[8], *last;
    uint32_t   crc32;
    ngx_str_t  str;

    str.data = (u_char *) luaL_checklstring(l, 1, &str.len);

    crc32 = ngx_crc32_long(str.data, str.len);

    crc[0] = crc32 >> 24;
    crc[1] = (u_char) (crc32 >> 16);
    crc[2] = (u_char) (crc32 >> 8);
    crc[3] = (u_char) crc32;

    last = ngx_hex_dump(hex, crc, 4);

    lua_pushlstring(l, (char *) hex, last - hex);

    return 1;
}


static int
ngx_lua_murmur_hash2(lua_State *l)
{
    u_char     hash[4], hex[8], *last;
    uint32_t   murmur;
    ngx_str_t  str;

    str.data = (u_char *) luaL_checklstring(l, 1, &str.len);

    murmur = ngx_murmur_hash2(str.data, str.len);

    hash[0] = murmur >> 24;
    hash[1] = (u_char) (murmur >> 16);
    hash[2] = (u_char) (murmur >> 8);
    hash[3] = (u_char) murmur;

    last = ngx_hex_dump(hex, hash, 4);

    lua_pushlstring(l, (char *) hex, last - hex);

    return 1;
}


static int
ngx_lua_md5(lua_State *l)
{
    u_char              *md5, *hex, *last;
    ngx_str_t            str;
    ngx_md5_t            ctx;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    str.data = (u_char *) luaL_checklstring(l, 1, &str.len);

    md5 = ngx_pnalloc(r->pool, 48);
    if (md5 == NULL) {
        return luaL_error(l, "ngx_palloc() failed");
    }

    hex = md5 + 16;

    ngx_md5_init(&ctx);
    ngx_md5_update(&ctx, str.data, str.len);
    ngx_md5_final(md5, &ctx);

    last = ngx_hex_dump(hex, md5, 16);

    lua_pushlstring(l, (char *) hex, last - hex);

    return 1;
}


static int
ngx_lua_sha1(lua_State *l)
{
    u_char              *sha1, *hex, *last;
    ngx_str_t            str;
    ngx_sha1_t           ctx;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    str.data = (u_char *) luaL_checklstring(l, 1, &str.len);

    sha1 = ngx_pnalloc(r->pool, 72);
    if (sha1 == NULL) {
        return luaL_error(l, "ngx_palloc() failed");
    }

    hex = sha1 + 24;

    ngx_sha1_init(&ctx);
    ngx_sha1_update(&ctx, str.data, str.len);
    ngx_sha1_final(sha1, &ctx);

    last = ngx_hex_dump(hex, sha1, 20);

    lua_pushlstring(l, (char *) hex, last - hex);

    return 1;
}
