
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_btt.h>
#include <ngx_lua.h>


static int ngx_lua_btt_index(lua_State *l);
static int ngx_lua_btt_torrents(lua_State *l);
static int ngx_lua_btt_peers(lua_State *l);
static int ngx_lua_btt_to_db_peers(lua_State *l);

static void ngx_lua_btt_create_table(lua_State *l, ngx_btt_peer_info_t *pi,
    int index);
static ngx_btt_ctx_t *ngx_lua_btt_get_ctx(ngx_lua_thread_t *thr);

static ngx_int_t ngx_lua_btt_module_init(ngx_cycle_t *cycle);


static ngx_lua_const_t  ngx_lua_btt_consts[] = {
    { NULL, 0 }
};


static luaL_Reg  ngx_lua_btt_methods[] = {
    { "torrents", ngx_lua_btt_torrents },
    { "peers", ngx_lua_btt_peers },
    { "to_db_peers", ngx_lua_btt_to_db_peers },
    { NULL, NULL }
};


ngx_module_t  ngx_lua_btt_module = {
    NGX_MODULE_V1,
    NULL,                                  /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_lua_btt_module_init,               /* init module */
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
        &ngx_lua_btt_module,
        NULL
    };

    return modules;
}
#endif


static int
ngx_lua_btt_index(lua_State *l)
{
    ngx_str_t          key;
    ngx_lua_thread_t  *thr;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua btt index");

    key.data = (u_char *) luaL_checklstring(l, -1, &key.len);

    switch (key.len) {

    case 5:
        break;

    case 8:
        break;

    case 11:
        break;

    default:
        break;
    }

    lua_pushnil(l);

    return 1;
}


static int
ngx_lua_btt_torrents(lua_State *l)
{
    u_char              buf[64], *p;
    ssize_t             n;
    ngx_uint_t          i;
    ngx_btt_ctx_t      *ctx;
    ngx_btt_conf_t     *bcf;
    ngx_lua_thread_t   *thr;
    ngx_btt_torrent_t  *t;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua btt torrents");

    ctx = ngx_lua_btt_get_ctx(thr);
    if (ctx == NULL) {
        lua_pushboolean(l, 0);
        return 1;
    }

    ctx->numwant = luaL_optint(l, 1, 30);
    ctx->numwant = ngx_min(ctx->numwant, ctx->torrents_n);

    bcf = (ngx_btt_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx, ngx_btt_module);

    n = ngx_btt_query_torrents(bcf, ctx);
    if (n == NGX_ERROR) {
        lua_pushboolean(l, 0);
        return 1;
    }

    lua_createtable(l, n, 0);

    for (i = 0; i < (ngx_uint_t) n; i++) {
        t = &ctx->torrents[i];

        lua_createtable(thr->l, 0, 1);

        p = ngx_hex_dump(buf, t->info_hash, sizeof(t->info_hash));
        lua_pushlstring(l, (char *) buf, p - buf);
        lua_setfield(l, -2, "info_hash");

        lua_rawseti(l, -2, i + 1);
    }

    return 1;
}


static int
ngx_lua_btt_peers(lua_State *l)
{
    u_char            *p, *last;
    size_t             len;
    ssize_t            n;
    ngx_uint_t         i;
    ngx_btt_ctx_t     *ctx;
    ngx_btt_conf_t    *bcf;
    ngx_lua_thread_t  *thr;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua btt peers");

    ctx = ngx_lua_btt_get_ctx(thr);
    if (ctx == NULL) {
        lua_pushboolean(l, 0);
        return 1;
    }

    p = (u_char *) luaL_checklstring(l, 1, &len);
    if (len != 40) {
        ngx_log_error(NGX_LOG_ALERT, thr->log, 0,
                      "invalid info_hash \"%*s\"", len, p);
        lua_pushboolean(l, 0);
        return 1;
    }

    last = p + len;
    i = 0;

    while (p < last) {
        ctx->info_hash[i++] = (u_char) ngx_hextoi(p, 2);
        p += 2;
    }

    ctx->numwant = luaL_optint(l, 2, 5);
    ctx->numwant = ngx_min(ctx->numwant, ctx->peers_n);

    bcf = (ngx_btt_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx, ngx_btt_module);

    n = ngx_btt_query_torrent_peers(bcf, ctx);
    if (n == NGX_ERROR) {
        lua_pushboolean(l, 0);
        return 1;
    }

    lua_createtable(l, n, 0);

    for (i = 0; i < (ngx_uint_t) n; i++) {
        ngx_lua_btt_create_table(l, &ctx->peers[i], i + 1);
    }

    return 1;
}


static int
ngx_lua_btt_to_db_peers(lua_State *l)
{
    ssize_t            n;
    ngx_uint_t         remove, i;
    ngx_btt_ctx_t     *ctx;
    ngx_btt_conf_t    *bcf;
    ngx_lua_thread_t  *thr;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua btt to db peers");

    ctx = ngx_lua_btt_get_ctx(thr);
    if (ctx == NULL) {
        lua_pushboolean(l, 0);
        return 1;
    }

    ctx->numwant = luaL_optint(l, 1, 5);
    ctx->numwant = ngx_min(ctx->numwant, ctx->peers_n);

    remove = luaL_optint(l, 2, 0);

    bcf = (ngx_btt_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx, ngx_btt_module);

    n = ngx_btt_query_to_db_peers(bcf, ctx, remove);
    if (n == NGX_ERROR) {
        lua_pushboolean(l, 0);
        return 1;
    }

    lua_createtable(l, n, 0);

    for (i = 0; i < (ngx_uint_t) n; i++) {
        ngx_lua_btt_create_table(l, &ctx->peers[i], i + 1);
    }

    return 1;
}


static void
ngx_lua_btt_create_table(lua_State *l, ngx_btt_peer_info_t *pi, int index)
{
    size_t     len;
    u_char     buf[128], *p, *last;
    in_addr_t  addr;

    last = buf + sizeof(buf);

    lua_createtable(l, 0, 16);

    p = ngx_hex_dump(buf, pi->info_hash, sizeof(pi->info_hash));
    lua_pushlstring(l, (char *) buf, p - buf);
    lua_setfield(l, -2, "info_hash_hex");

    lua_pushlstring(l, (char *) pi->info_hash, sizeof(pi->info_hash));
    lua_setfield(l, -2, "info_hash");

    p = ngx_hex_dump(buf, pi->peer_id, sizeof(pi->peer_id));
    lua_pushlstring(l, (char *) buf, p - buf);
    lua_setfield(l, -2, "peer_id_hex");

    lua_pushlstring(l, (char *) pi->peer_id, sizeof(pi->peer_id));
    lua_setfield(l, -2, "peer_id");

    addr = htonl(pi->internal_ip);
    len = ngx_inet_ntop(AF_INET, &addr, buf, last - buf);
    lua_pushlstring(l, (char *) buf, len);
    lua_setfield(l, -2, "internal_ip_str");

    lua_pushinteger(l, pi->internal_ip);
    lua_setfield(l, -2, "internal_ip");

    lua_pushinteger(l, pi->internal_port);
    lua_setfield(l, -2, "internal_port");

    addr = htonl(pi->external_ip);
    len = ngx_inet_ntop(AF_INET, &addr, buf, last - buf);
    lua_pushlstring(l, (char *) buf, len);
    lua_setfield(l, -2, "external_ip_str");

    lua_pushinteger(l, pi->external_ip);
    lua_setfield(l, -2, "external_ip");

    lua_pushinteger(l, pi->external_port);
    lua_setfield(l, -2, "external_port");

    p = ngx_slprintf(buf, last, "%uL", pi->uploaded);
    lua_pushlstring(l, (char *) buf, p - buf);
    lua_setfield(l, -2, "uploaded");

    p = ngx_slprintf(buf, last, "%uL", pi->downloaded);
    lua_pushlstring(l, (char *) buf, p - buf);
    lua_setfield(l, -2, "downloaded");

    p = ngx_slprintf(buf, last, "%uL", pi->left);
    lua_pushlstring(l, (char *) buf, p - buf);
    lua_setfield(l, -2, "left");

    lua_rawseti(l, -2, index);
}


static ngx_btt_ctx_t *
ngx_lua_btt_get_ctx(ngx_lua_thread_t *thr)
{
    ngx_btt_ctx_t  *ctx;

    ctx = ngx_lua_thread_get_module_ctx(thr, ngx_lua_btt_module);
    if (ctx != NULL) {
        return ctx;
    }

    ctx = ngx_pcalloc(thr->pool, sizeof(ngx_btt_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->pool = thr->pool;
    ctx->log = thr->log;

    /* TODO: configurable the number of torrents and peers */

    ctx->torrents_n = 100;
    ctx->torrents = ngx_palloc(thr->pool,
                               sizeof(ngx_btt_torrent_t) * ctx->torrents_n);
    if (ctx->torrents == NULL) {
        return NULL;
    }

    ctx->peers_n = 300;
    ctx->peers = ngx_palloc(thr->pool,
                            sizeof(ngx_btt_peer_info_t) * ctx->peers_n);
    if (ctx->peers == NULL) {
        return NULL;
    }

    ngx_lua_thread_set_ctx(thr, ctx, ngx_lua_btt_module);

    return ctx;
}


static ngx_int_t
ngx_lua_btt_module_init(ngx_cycle_t *cycle)
{
    int              n;
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua btt module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    lua_getglobal(lcf->l, NGX_LUA_TABLE);

    n = sizeof(ngx_lua_btt_consts) / sizeof(ngx_lua_const_t) - 1;
    n += sizeof(ngx_lua_btt_methods) / sizeof(luaL_Reg) - 1;

    lua_createtable(lcf->l, 0, n);

    for (n = 0; ngx_lua_btt_consts[n].name != NULL; n++) {
        lua_pushinteger(lcf->l, ngx_lua_btt_consts[n].value);
        lua_setfield(lcf->l, -2, ngx_lua_btt_consts[n].name);
    }

    for (n = 0; ngx_lua_btt_methods[n].name != NULL; n++) {
        lua_pushcfunction(lcf->l, ngx_lua_btt_methods[n].func);
        lua_setfield(lcf->l, -2, ngx_lua_btt_methods[n].name);
    }

    lua_createtable(lcf->l, 0, 1);
    lua_pushcfunction(lcf->l, ngx_lua_btt_index);
    lua_setfield(lcf->l, -2, "__index");
    lua_setmetatable(lcf->l, -2);

    lua_setfield(lcf->l, -2, "btt");

    lua_pop(lcf->l, 1);

    return NGX_OK;
}
