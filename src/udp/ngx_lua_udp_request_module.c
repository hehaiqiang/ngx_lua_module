
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_udp_module.h>


static int ngx_lua_udp_request_index(lua_State *l);

static ngx_int_t ngx_lua_udp_request_module_init(ngx_cycle_t *cycle);


ngx_module_t  ngx_lua_udp_request_module = {
    NGX_MODULE_V1,
    NULL,                                  /* module context */
    NULL,                                  /* module directives */
    NGX_UDP_MODULE,                        /* module type */
    NULL,                                  /* init master */
    ngx_lua_udp_request_module_init,       /* init module */
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
        &ngx_lua_udp_request_module,
        NULL
    };

    return modules;
}
#endif


static int
ngx_lua_udp_request_index(lua_State *l)
{
    u_char             *p;
    ngx_str_t           key, *addr;
    ngx_lua_thread_t   *thr;
    ngx_lua_udp_ctx_t  *ctx;
    ngx_udp_session_t  *s;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua udp request index");

    ctx = thr->module_ctx;
    s = ctx->s;

    key.data = (u_char *) luaL_checklstring(l, -1, &key.len);

    switch (key.len) {

    case 4:

        if (ngx_strncmp(key.data, "data", 4) == 0) {
            lua_pushlstring(l, (char *) s->buffer->pos,
                            s->buffer->last - s->buffer->pos);
            return 1;
        }

        break;

    case 11:

        addr = &s->connection->addr_text;

        if (ngx_strncmp(key.data, "remote_addr", 11) == 0) {
            p = ngx_strlchr(addr->data, addr->data + addr->len, ':');
            if (p == NULL) {
                /* TODO: error handling */
                break;
            }

            lua_pushlstring(l, (char *) addr->data, p - addr->data);
            return 1;
        }

        if (ngx_strncmp(key.data, "remote_port", 11) == 0) {
            p = ngx_strlchr(addr->data, addr->data + addr->len, ':');
            if (p == NULL) {
                /* TODO: error handling */
                break;
            }

            p++;

            lua_pushlstring(l, (char *) p, addr->data + addr->len - p);
            return 1;
        }

        addr = s->addr_text;

        if (ngx_strncmp(key.data, "server_addr", 11) == 0) {
            p = ngx_strlchr(addr->data, addr->data + addr->len, ':');
            if (p == NULL) {
                /* TODO: error handling */
                break;
            }

            lua_pushlstring(l, (char *) addr->data, p - addr->data);
            return 1;
        }

        if (ngx_strncmp(key.data, "server_port", 11) == 0) {
            p = ngx_strlchr(addr->data, addr->data + addr->len, ':');
            if (p == NULL) {
                /* TODO: error handling */
                break;
            }

            p++;

            lua_pushlstring(l, (char *) p, addr->data + addr->len - p);
            return 1;
        }

        break;

    default:
        break;
    }

    lua_pushnil(l);

    return 1;
}


static ngx_int_t
ngx_lua_udp_request_module_init(ngx_cycle_t *cycle)
{
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "lua udp request module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    lua_getglobal(lcf->l, NGX_LUA_TABLE);
    lua_getfield(lcf->l, -1, NGX_LUA_UDP_TABLE);

    lua_newtable(lcf->l);

    lua_createtable(lcf->l, 0, 1);
    lua_pushcfunction(lcf->l, ngx_lua_udp_request_index);
    lua_setfield(lcf->l, -2, "__index");
    lua_setmetatable(lcf->l, -2);

    lua_setfield(lcf->l, -2, "request");

    lua_pop(lcf->l, 2);

    return NGX_OK;
}
