
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua.h>


static void ngx_lua_debug_hook(lua_State *l, lua_Debug *ar);
static ngx_int_t ngx_lua_debug_get_info(ngx_lua_thread_t *thr, lua_State *l,
    lua_Debug *ar);
static ngx_int_t ngx_lua_debug_get_stack(ngx_lua_thread_t *thr, lua_State *l,
    lua_Debug *ar);
static ngx_int_t ngx_lua_debug_get_upvalue(ngx_lua_thread_t *thr, lua_State *l,
    lua_Debug *ar);
static ngx_int_t ngx_lua_debug_get_local(ngx_lua_thread_t *thr, lua_State *l,
    lua_Debug *ar);


ngx_int_t
ngx_lua_debug_start(ngx_lua_thread_t *thr)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua debug start");

    /* TODO: LUA_MASKCOUNT|LUA_MASKRET|LUA_MASKLINE */

    lua_sethook(thr->l, ngx_lua_debug_hook, LUA_MASKCALL, 0);

    return NGX_OK;
}


ngx_int_t
ngx_lua_debug_stop(ngx_lua_thread_t *thr)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua debug stop");

    lua_sethook(thr->l, ngx_lua_debug_hook, 0, 0);

    return NGX_OK;
}


static void
ngx_lua_debug_hook(lua_State *l, lua_Debug *ar)
{
    ngx_lua_thread_t  *thr;

    thr = ngx_lua_thread(l);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua debug hook");

    /* TODO */

    switch (ar->event) {

    case LUA_HOOKCALL:
        break;

    case LUA_HOOKRET:
        break;

    case LUA_HOOKTAILRET:
        break;

    case LUA_HOOKLINE:
        break;

    case LUA_HOOKCOUNT:
        break;

    default:
        ngx_log_error(NGX_LOG_ALERT, thr->log, 0, "invalid hook event");
        break;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, thr->log, 0,
                   "current line %d", ar->currentline);

#if 0
    ngx_lua_debug_get_info(thr, l, ar);
#endif

    ngx_lua_debug_get_stack(thr, l, ar);

    ngx_lua_debug_get_upvalue(thr, l, ar);

    ngx_lua_debug_get_local(thr, l, ar);
}


static ngx_int_t
ngx_lua_debug_get_info(ngx_lua_thread_t *thr, lua_State *l, lua_Debug *ar)
{
    int  rc;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua debug get info");

    /* TODO: "fL" */

    rc = lua_getinfo(l, "nSlu", ar);
    if (rc == 0) {
        ngx_log_error(NGX_LOG_ALERT, thr->log, 0, "lua_getinfo() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_lua_debug_get_stack(ngx_lua_thread_t *thr, lua_State *l, lua_Debug *ar)
{
    int  level, rc;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua debug get stack");

    level = 0;

    do {

        rc = lua_getstack(l, level, ar);
        if (rc == 0) {
            break;
        }

        ngx_lua_debug_get_info(thr, l, ar);

        level++;

    } while (1);

    return NGX_OK;
}


static ngx_int_t
ngx_lua_debug_get_upvalue(ngx_lua_thread_t *thr, lua_State *l, lua_Debug *ar)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua debug get upvalue");

    /* lua_getupvalue */

    return NGX_OK;
}


static ngx_int_t
ngx_lua_debug_get_local(ngx_lua_thread_t *thr, lua_State *l, lua_Debug *ar)
{
    int          n, type;
    char        *name, *type_name, *sval;
    lua_Number   nval;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua debug get local");

    n = 1;

    do {

        name = (char *) lua_getlocal(l, ar, n);
        if (name == NULL) {
            break;
        }

        type = lua_type(l, -1);

        switch (type) {

        case LUA_TNIL:
            break;
        case LUA_TNUMBER:
            nval = luaL_checknumber(l, -1);
            break;
        case LUA_TBOOLEAN:
            break;
        case LUA_TSTRING:
            sval = (char *) luaL_checkstring(l, -1);
            /* luaL_checklstring */
            break;
        case LUA_TTABLE:
        case LUA_TFUNCTION:
        case LUA_TUSERDATA:
        case LUA_TTHREAD:
        case LUA_TLIGHTUSERDATA:
        case LUA_TNONE:
        default:
            break;
        }

        type_name = (char *) lua_typename(l, type);

        lua_pop(l, 1);

        n++;

    } while (1);

    return NGX_OK;
}
