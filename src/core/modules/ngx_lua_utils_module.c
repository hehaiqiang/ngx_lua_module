
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_md5.h>
#include <ngx_sha1.h>
#include <ngx_lua.h>


typedef struct {
    ngx_event_t    event;
} ngx_lua_utils_ctx_t;


extern int ngx_lua_http(lua_State *l);

static int ngx_lua_escape_uri(lua_State *l);
static int ngx_lua_unescape_uri(lua_State *l);
static int ngx_lua_encode_base64(lua_State *l);
static int ngx_lua_decode_base64(lua_State *l);
static int ngx_lua_crc16(lua_State *l);
static int ngx_lua_crc32(lua_State *l);
static int ngx_lua_murmur_hash2(lua_State *l);
static int ngx_lua_md5(lua_State *l);
static int ngx_lua_sha1(lua_State *l);

static int ngx_lua_sleep(lua_State *l);
static void ngx_lua_sleep_handler(ngx_event_t *ev);
static void ngx_lua_sleep_cleanup(void *data);

static ngx_int_t ngx_lua_utils_module_init(ngx_cycle_t *cycle);


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
    { "sleep", ngx_lua_sleep },
    { "http", ngx_lua_http },

#if 0
    iconv
#endif

    { NULL, NULL }
};


ngx_module_t  ngx_lua_utils_module = {
    NGX_MODULE_V1,
    NULL,                                  /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_lua_utils_module_init,             /* init module */
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
        &ngx_lua_utils_module,
        NULL
    };

    return modules;
}
#endif


static int
ngx_lua_escape_uri(lua_State *l)
{
    size_t             len;
    u_char            *p, *last;
    ngx_str_t          str;
    ngx_lua_thread_t  *thr;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua escape uri");

    str.data = (u_char *) luaL_checklstring(l, 1, &str.len);

    len = ngx_escape_uri(NULL, str.data, str.len, 0);
    if (len == 0) {
        lua_pushlstring(l, (char *) str.data, str.len);
        return 1;
    }

    len = str.len + len * 2;

    p = ngx_pnalloc(thr->pool, len);
    if (p == NULL) {
        lua_pushboolean(l, 0);
        lua_pushstring(l, "ngx_pnalloc() failed");
        return 2;
    }

    last = (u_char *) ngx_escape_uri(p, str.data, str.len, 0);

    lua_pushlstring(l, (char *) p, last - p);

    return 1;
}


static int
ngx_lua_unescape_uri(lua_State *l)
{
    u_char            *dst, *p;
    ngx_str_t          str;
    ngx_lua_thread_t  *thr;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua unescape uri");

    str.data = (u_char *) luaL_checklstring(l, 1, &str.len);

    p = ngx_pnalloc(thr->pool, str.len);
    if (p == NULL) {
        lua_pushboolean(l, 0);
        lua_pushstring(l, "ngx_pnalloc() failed");
        return 2;
    }

    dst = p;

    ngx_unescape_uri(&dst, &str.data, str.len, 0);

    lua_pushlstring(l, (char *) p, dst - p);

    return 1;
}


static int
ngx_lua_encode_base64(lua_State *l)
{
    ngx_str_t          dst, src;
    ngx_lua_thread_t  *thr;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua encode base64");

    src.data = (u_char *) luaL_checklstring(l, 1, &src.len);

    dst.len = ngx_base64_encoded_length(src.len);

    dst.data = ngx_pnalloc(thr->pool, dst.len);
    if (dst.data == NULL) {
        lua_pushboolean(l, 0);
        lua_pushstring(l, "ngx_pnalloc() failed");
        return 2;
    }

    ngx_encode_base64(&dst, &src);

    lua_pushlstring(l, (char *) dst.data, dst.len);

    return 1;
}


static int
ngx_lua_decode_base64(lua_State *l)
{
    ngx_str_t          dst, src;
    ngx_lua_thread_t  *thr;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua decode base64");

    src.data = (u_char *) luaL_checklstring(l, 1, &src.len);

    dst.len = ngx_base64_decoded_length(src.len);

    dst.data = ngx_pnalloc(thr->pool, dst.len);
    if (dst.data == NULL) {
        lua_pushboolean(l, 0);
        lua_pushstring(l, "ngx_pnalloc() failed");
        return 2;
    }

    if (ngx_decode_base64(&dst, &src) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, thr->log, 0, "ngx_decode_base64() failed");
        lua_pushboolean(l, 0);
        lua_pushstring(l, "ngx_decode_base64() failed");
        return 2;
    }

    lua_pushlstring(l, (char *) dst.data, dst.len);

    return 1;
}


static int
ngx_lua_crc16(lua_State *l)
{
    u_char             crc[4], hex[8], *last;
    uint32_t           crc16;
    ngx_str_t          str;
    ngx_lua_thread_t  *thr;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua crc16");

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
    u_char             crc[4], hex[8], *last;
    uint32_t           crc32;
    ngx_str_t          str;
    ngx_lua_thread_t  *thr;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua crc32");

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
    u_char             hash[4], hex[8], *last;
    uint32_t           murmur;
    ngx_str_t          str;
    ngx_lua_thread_t  *thr;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua murmur hash2");

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
    u_char            *md5, *hex, *last;
    ngx_str_t          str;
    ngx_md5_t          ctx;
    ngx_lua_thread_t  *thr;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua md5");

    str.data = (u_char *) luaL_checklstring(l, 1, &str.len);

    md5 = ngx_pnalloc(thr->pool, 48);
    if (md5 == NULL) {
        lua_pushboolean(l, 0);
        lua_pushstring(l, "ngx_palloc() failed");
        return 2;
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
    u_char            *sha1, *hex, *last;
    ngx_str_t          str;
    ngx_sha1_t         ctx;
    ngx_lua_thread_t  *thr;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua sha1");

    str.data = (u_char *) luaL_checklstring(l, 1, &str.len);

    sha1 = ngx_pnalloc(thr->pool, 72);
    if (sha1 == NULL) {
        lua_pushboolean(l, 0);
        lua_pushstring(l, "ngx_palloc() failed");
        return 2;
    }

    hex = sha1 + 24;

    ngx_sha1_init(&ctx);
    ngx_sha1_update(&ctx, str.data, str.len);
    ngx_sha1_final(sha1, &ctx);

    last = ngx_hex_dump(hex, sha1, 20);

    lua_pushlstring(l, (char *) hex, last - hex);

    return 1;
}


static int
ngx_lua_sleep(lua_State *l)
{
    ngx_int_t             time;
    ngx_str_t             str;
    ngx_lua_thread_t     *thr;
    ngx_pool_cleanup_t   *cln;
    ngx_lua_utils_ctx_t  *ctx;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua sleep");

    if (lua_type(l, 1) == LUA_TSTRING) {
        str.data = (u_char *) luaL_checklstring(l, 1, &str.len);

        time = ngx_parse_time(&str, 0);
        if (time == NGX_ERROR) {
            lua_pushboolean(l, 0);
            lua_pushfstring(l, "invalid time \"%s\"", str.data);
            return 2;
        }

    } else {
        time = luaL_checkint(l, 1);

        /* TODO: error handling */
    }

    ctx = ngx_lua_thread_get_module_ctx(thr, ngx_lua_utils_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(thr->pool, sizeof(ngx_lua_utils_ctx_t));
        if (ctx == NULL) {
            lua_pushboolean(l, 0);
            lua_pushstring(l, "ngx_pcalloc() failed");
            return 2;
        }

        ngx_lua_thread_set_ctx(thr, ctx, ngx_lua_utils_module);
    }

    if (ctx->event.handler == NULL) {
        ctx->event.handler = ngx_lua_sleep_handler;
        ctx->event.data = thr;
        ctx->event.log = thr->log;

        cln = ngx_pool_cleanup_add(thr->pool, 0);
        if (cln == NULL) {
            lua_pushboolean(l, 0);
            lua_pushstring(l, "ngx_pool_cleanup_add() failed");
            return 2;
        }

        cln->handler = ngx_lua_sleep_cleanup;
        cln->data = thr;
    }

    ngx_add_timer(&ctx->event, time);

    return lua_yield(l, 0);
}


static void
ngx_lua_sleep_handler(ngx_event_t *ev)
{
    ngx_int_t          rc;
    ngx_lua_thread_t  *thr;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "lua sleep handler");

    thr = ev->data;

    lua_pushboolean(thr->l, 1);

    rc = ngx_lua_thread_run(thr, 1);
    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_lua_finalize(thr, rc);
}


static void
ngx_lua_sleep_cleanup(void *data)
{
    ngx_lua_thread_t *thr = data;

    ngx_lua_utils_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua sleep cleanup");

    ctx = ngx_lua_thread_get_module_ctx(thr, ngx_lua_utils_module);

    if (ctx->event.timer_set) {
        ngx_event_del_timer(&ctx->event);
    }
}


static ngx_int_t
ngx_lua_utils_module_init(ngx_cycle_t *cycle)
{
    int              n;
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua utils module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    lua_getglobal(lcf->l, NGX_LUA_TABLE);

    n = sizeof(ngx_lua_consts) / sizeof(ngx_lua_const_t) - 1;
    n += sizeof(ngx_lua_methods) / sizeof(luaL_Reg) - 1;

    lua_createtable(lcf->l, 0, n);

    for (n = 0; ngx_lua_consts[n].name != NULL; n++) {
        lua_pushinteger(lcf->l, ngx_lua_consts[n].value);
        lua_setfield(lcf->l, -2, ngx_lua_consts[n].name);
    }

    for (n = 0; ngx_lua_methods[n].name != NULL; n++) {
        lua_pushcfunction(lcf->l, ngx_lua_methods[n].func);
        lua_setfield(lcf->l, -2, ngx_lua_methods[n].name);
    }

    lua_setfield(lcf->l, -2, "utils");

    lua_pop(lcf->l, 1);

    return NGX_OK;
}
