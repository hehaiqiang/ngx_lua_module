
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_module.h>


#define NGX_LUA_KEY_REQ   "ngx_lua_key_req"
#define NGX_LUA_KEY_REF   "ngx_lua_key_ref"
#define NGX_LUA_KEY_CODE  "ngx_lua_key_code"


static void ngx_lua_set_path(lua_State *l, char *key, ngx_str_t *value);
static void ngx_lua_api_init(lua_State *l);
static int ngx_lua_print(lua_State *l);
static int ngx_lua_panic(lua_State *l);


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


ngx_int_t
ngx_lua_state_new(ngx_conf_t *cf, ngx_lua_main_conf_t *lmcf)
{
    lua_State  *l;

    l = luaL_newstate();
    if (l == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "luaL_newstate() failed");
        return NGX_ERROR;
    }

    lua_atpanic(l, ngx_lua_panic);

    luaL_openlibs(l);

    lua_getglobal(l, "package");

    if (!lua_istable(l, -1)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the table \"package\" not found");
        lua_close(l);
        return NGX_ERROR;
    }

    if (lmcf->path.len > 0) {
        ngx_lua_set_path(l, "path", &lmcf->path);
    }

    if (lmcf->cpath.len > 0) {
        ngx_lua_set_path(l, "cpath", &lmcf->cpath);
    }

    lua_remove(l, -1);

    ngx_lua_api_init(l);

    lua_newtable(l);
    lua_setfield(l, LUA_REGISTRYINDEX, NGX_LUA_KEY_REF);

    lmcf->l = l;

    return NGX_OK;
}


void
ngx_lua_state_close(void *data)
{
    lua_State *l = data;

    lua_close(l);
}


ngx_int_t
ngx_lua_thread_new(ngx_http_request_t *r, ngx_lua_ctx_t *ctx)
{
    int                   top;
    lua_State            *l;
    ngx_lua_main_conf_t  *lmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lua thread new");

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_module);

    top = lua_gettop(lmcf->l);
    lua_getfield(lmcf->l, LUA_REGISTRYINDEX, NGX_LUA_KEY_REF);

    l = lua_newthread(lmcf->l);
    if (l == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "lua_newthread() failed");
        lua_pop(lmcf->l, 1);
        return NGX_ERROR;
    }

    lua_newtable(l);
    lua_createtable(l, 0, 1);
    lua_pushvalue(l, LUA_GLOBALSINDEX);
    lua_setfield(l, -2, "__index");
    lua_setmetatable(l, -2);
    lua_replace(l, LUA_GLOBALSINDEX);

    ctx->ref = luaL_ref(lmcf->l, -2);
    if (ctx->ref == LUA_NOREF) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "luaL_ref() return LUA_NOREF");
        lua_settop(lmcf->l, top);
        return NGX_ERROR;
    }

    lua_pop(lmcf->l, 1);

    lua_xmove(lmcf->l, l, 1);

    lua_pushvalue(l, LUA_GLOBALSINDEX);
    lua_setfenv(l, -2);

    lua_pushvalue(l, -1);
    lua_setglobal(l, NGX_LUA_KEY_CODE);

    lua_pushlightuserdata(l, r);
    lua_setglobal(l, NGX_LUA_KEY_REQ);

    ctx->l = l;

    return NGX_OK;
}


void
ngx_lua_thread_close(ngx_http_request_t *r, ngx_lua_ctx_t *ctx)
{
    lua_State            *l;
    ngx_lua_main_conf_t  *lmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua thread close");

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_module);

    lua_getfield(lmcf->l, LUA_REGISTRYINDEX, NGX_LUA_KEY_REF);

    lua_rawgeti(lmcf->l, -1, ctx->ref);
    l = lua_tothread(lmcf->l, -1);
    lua_pop(lmcf->l, 1);

    lua_getglobal(l, NGX_LUA_KEY_CODE);
    lua_getfenv(l, -1);
    lua_xmove(l, lmcf->l, 1);
    lua_newtable(l);
    lua_setfenv(l, -2);

    do {
        lua_settop(l, 0);
    } while (lua_resume(l, 0) == LUA_YIELD);

    lua_settop(l, 0);
    lua_getglobal(l, NGX_LUA_KEY_CODE);
    lua_xmove(lmcf->l, l, 1);
    lua_setfenv(l, -2);
    lua_pop(l, 1);

    luaL_unref(lmcf->l, -1, ctx->ref);
    lua_pop(lmcf->l, 1);
}


ngx_int_t
ngx_lua_thread_run(ngx_http_request_t *r, ngx_lua_ctx_t *ctx, int n)
{
    int                   rc;
    ngx_str_t             str;
    ngx_lua_main_conf_t  *lmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lua thread run");

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_module);

    lua_atpanic(lmcf->l, ngx_lua_panic);

    rc = lua_resume(ctx->l, n);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua_resume() rc:%d", rc);

    switch (rc) {
    case 0:
        return NGX_OK;
    case LUA_YIELD:
        lua_settop(ctx->l, 0);
        return NGX_AGAIN;
    case LUA_ERRRUN:
    case LUA_ERRSYNTAX:
    case LUA_ERRMEM:
    case LUA_ERRERR:
    default:
        break;
    }

    if (lua_isstring(ctx->l, -1)) {
        str.data = (u_char *) lua_tolstring(ctx->l, -1, &str.len);
        ngx_lua_output(r, str.data, str.len);

        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "lua_resume() \"%V\" (rc:%d)", &str, rc);
    }

    return NGX_ERROR;
}


ngx_http_request_t *
ngx_lua_request(lua_State *l)
{
    ngx_http_request_t  *r;

    lua_getglobal(l, NGX_LUA_KEY_REQ);
    r = lua_touserdata(l, -1);
    lua_pop(l, 1);

    if (r == NULL) {
        luaL_error(l, "r is null");
    }

    return r;
}


ngx_int_t
ngx_lua_output(ngx_http_request_t *r, u_char *buf, size_t size)
{
    size_t          n;
    ngx_buf_t      *b;
    ngx_chain_t    *cl;
    ngx_lua_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_lua_module);

    if (ctx->last == NULL
        || (size_t) (ctx->last->buf->end - ctx->last->buf->last) < size)
    {
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        n = ngx_max(size, ngx_pagesize);

        cl->buf = ngx_create_temp_buf(r->pool, n);
        if (cl->buf == NULL) {
            return NGX_ERROR;
        }

        cl->next = NULL;

        if (ctx->last != NULL) {
            ctx->last->next = cl;
        }

        ctx->last = cl;

        if (ctx->out == NULL) {
            ctx->out = cl;
        }
    }

    b = ctx->last->buf;
    b->last = ngx_copy(b->last, buf, size);

    return NGX_OK;
}


void
ngx_lua_finalize(ngx_http_request_t *r, ngx_int_t rc)
{
    size_t          size;
    ngx_chain_t    *cl;
    ngx_lua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lua finalize");

    ctx = ngx_http_get_module_ctx(r, ngx_lua_module);

    if (r->headers_out.content_type.len == 0) {
        ngx_str_set(&r->headers_out.content_type, "text/html");
    }

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            ngx_http_finalize_request(r, rc);
            return;
        }
    }

    size = 0;

    for (cl = ctx->out; cl != NULL; cl = cl->next) {
        size += cl->buf->last - cl->buf->pos;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = size;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    if (ctx->out != NULL) {
        ctx->last->buf->last_buf = 1;

        rc = ngx_http_output_filter(r, ctx->out);

    } else {
        rc = ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    ngx_http_finalize_request(r, rc);
}


static void
ngx_lua_set_path(lua_State *l, char *key, ngx_str_t *value)
{
    char  *old, *new, *temp;

    lua_getfield(l, -1, key);
    old = (char *) lua_tostring(l, -1);

    lua_pushlstring(l, (char *) value->data, value->len);
    new = (char *) lua_tostring(l, -1);

    temp = (char *) luaL_gsub(l, new, ";;", ";\0;");
    luaL_gsub(l, temp, "\0", old);
    lua_remove(l, -2);

    lua_setfield(l, -4, key);

    lua_pop(l, 2);
}


static void
ngx_lua_api_init(lua_State *l)
{
    int  n;

    lua_pushnil(l);
    lua_setglobal(l, "coroutine");

    lua_register(l, "print", ngx_lua_print);

    n = sizeof(ngx_lua_consts) / sizeof(ngx_lua_const_t) - 1;

    lua_createtable(l, 5, n);

    for (n = 0; ngx_lua_consts[n].name != NULL; n++) {
        lua_pushinteger(l, ngx_lua_consts[n].value);
        lua_setfield(l, -2, ngx_lua_consts[n].name);
    }

    ngx_lua_dbd_api_init(l);
    ngx_lua_logger_api_init(l);
    ngx_lua_request_api_init(l);
    ngx_lua_response_api_init(l);
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
ngx_lua_panic(lua_State *l)
{
    ngx_str_t            str;
    ngx_log_t           *log;
    ngx_http_request_t  *r;

    lua_getglobal(l, NGX_LUA_KEY_REQ);
    r = lua_touserdata(l, -1);
    lua_pop(l, 1);

    str.data = (u_char *) lua_tolstring(l, -1, &str.len);

    if (r != NULL) {
        ngx_lua_output(r, str.data, str.len);

        log = r->connection->log;

    } else {
        log = ngx_cycle->log;
    }

    ngx_log_error(NGX_LOG_ALERT, log, 0, "%V", &str);

    return 0;
}
