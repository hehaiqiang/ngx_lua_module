
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua.h>


typedef struct {
    ngx_queue_t           queue;
    ngx_uint_t            line;
} ngx_lua_debug_break_point_t;


typedef struct {
    ngx_rbtree_node_t     node;
    ngx_queue_t           queue;
    ngx_str_t             file;
    ngx_queue_t           break_points;
} ngx_lua_debug_break_points_t;


typedef struct {
    ngx_queue_t           queue;
    ngx_str_t             name;
    void                 *value;
    ngx_uint_t            type;
} ngx_lua_debug_variable_t;


typedef struct {
    ngx_queue_t           queue;

    ngx_str_t             file;
    ngx_str_t             function;
    ngx_uint_t            start_line;
    ngx_uint_t            end_line;
    ngx_uint_t            current_line;

    ngx_queue_t           upvalues;
    ngx_queue_t           local_vars;
} ngx_lua_debug_stack_t;


typedef struct {
    ngx_rbtree_t          break_point_rbtree;
    ngx_rbtree_node_t     break_point_sentinel;
    ngx_queue_t           break_point_queue;
    ngx_rbtree_t          watch_rbtree;
    ngx_rbtree_node_t     watch_sentinel;
    ngx_queue_t           watch_queue;
    ngx_queue_t           stack;

    ngx_uint_t            running;
    ngx_uint_t            done;
} ngx_lua_debug_t;


typedef struct {
    ngx_flag_t            enable;
    ngx_uint_t            debugger;
    ngx_str_t             name;
    size_t                size;

    ngx_lua_debug_t      *debug;
    ngx_slab_pool_t      *pool;
    ngx_shm_zone_t       *zone;

    ngx_event_t           event;
    ngx_lua_thread_t     *thr;
} ngx_lua_debug_conf_t;


static void ngx_lua_debug_hook(lua_State *l, lua_Debug *ar);
static ngx_int_t ngx_lua_debug_get_info(ngx_lua_thread_t *thr, lua_State *l,
    lua_Debug *ar);
static ngx_int_t ngx_lua_debug_get_stack(ngx_lua_thread_t *thr, lua_State *l,
    lua_Debug *ar);
static ngx_int_t ngx_lua_debug_get_upvalue(ngx_lua_thread_t *thr, lua_State *l,
    lua_Debug *ar);
static ngx_int_t ngx_lua_debug_get_local(ngx_lua_thread_t *thr, lua_State *l,
    lua_Debug *ar);

static void ngx_lua_debug_event(ngx_event_t *ev);

static ngx_int_t ngx_lua_debug_init(ngx_shm_zone_t *shm_zone, void *data);

static ngx_int_t ngx_lua_debug_module_init(ngx_cycle_t *cycle);
static void *ngx_lua_debug_create_conf(ngx_cycle_t *cycle);
static char *ngx_lua_debug_init_conf(ngx_cycle_t *cycle, void *conf);
static char *ngx_lua_debug(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_lua_const_t  ngx_lua_debug_consts[] = {
    { NULL, 0 }
};


static luaL_Reg  ngx_lua_debug_methods[] = {
    { NULL, NULL }
};


static ngx_command_t  ngx_lua_debug_commands[] = {

    { ngx_string("lua_debug"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE2,
      ngx_lua_debug,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_lua_debug_module_ctx = {
    ngx_string("debug"),
    ngx_lua_debug_create_conf,
    ngx_lua_debug_init_conf,
};


ngx_module_t  ngx_lua_debug_module = {
    NGX_MODULE_V1,
    &ngx_lua_debug_module_ctx,             /* module context */
    ngx_lua_debug_commands,                /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_lua_debug_module_init,             /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_lua_debug_start(ngx_lua_thread_t *thr)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua debug start");

    /* TODO: LUA_MASKCOUNT|LUA_MASKRET */
    /* LUA_MASKCALL */

#if 0
    lua_sethook(thr->l, ngx_lua_debug_hook, LUA_MASKLINE, 0);
#endif

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

#if 1
    ngx_lua_debug_get_info(thr, l, ar);
#endif

    ngx_lua_debug_get_local(thr, l, ar);

    ngx_lua_debug_get_upvalue(thr, l, ar);

    ngx_lua_debug_get_stack(thr, l, ar);
}


static ngx_int_t
ngx_lua_debug_get_info(ngx_lua_thread_t *thr, lua_State *l, lua_Debug *ar)
{
    int  rc;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua debug get info");

    /* TODO: "fL" */

    rc = lua_getinfo(l, "nSl", ar);
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

        rc = lua_getinfo(l, "nSl", ar);
        if (rc == 0) {
            ngx_log_error(NGX_LOG_ALERT, thr->log, 0, "lua_getinfo() failed");
            return NGX_ERROR;
        }

        level++;

    } while (1);

    return NGX_OK;
}


static ngx_int_t
ngx_lua_debug_get_upvalue(ngx_lua_thread_t *thr, lua_State *l, lua_Debug *ar)
{
    int  rc;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua debug get upvalue");

    rc = lua_getinfo(l, "u", ar);
    if (rc == 0) {
        ngx_log_error(NGX_LOG_ALERT, thr->log, 0, "lua_getinfo() failed");
        return NGX_ERROR;
    }

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


static void
ngx_lua_debug_event(ngx_event_t *ev)
{
    /* TODO */
}


static ngx_int_t
ngx_lua_debug_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_lua_debug_conf_t *oldcf = data;

    size_t                 len;
    ngx_lua_debug_conf_t  *ldcf;

    ldcf = shm_zone->data;

    if (oldcf) {
        ldcf->debug = oldcf->debug;
        ldcf->pool = oldcf->pool;
        return NGX_OK;
    }

    ldcf->pool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ldcf->debug = ldcf->pool->data;
        return NGX_OK;
    }

    ldcf->debug = ngx_slab_alloc(ldcf->pool, sizeof(ngx_lua_debug_t));
    if (ldcf->debug == NULL) {
        return NGX_ERROR;
    }

    ldcf->pool->data = ldcf->debug;

    /* TODO */

    ngx_queue_init(&ldcf->debug->stack);

    len = sizeof(" in lua debug \"\"") + shm_zone->shm.name.len;

    ldcf->pool->log_ctx = ngx_slab_alloc(ldcf->pool, len);
    if (ldcf->pool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ldcf->pool->log_ctx, " in lua debug \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


static ngx_int_t
ngx_lua_debug_module_init(ngx_cycle_t *cycle)
{
    int              n;
    ngx_lua_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua debug module init");

    lcf = (ngx_lua_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_lua_module);

    lua_getglobal(lcf->l, NGX_LUA_TABLE);

    n = sizeof(ngx_lua_debug_consts) / sizeof(ngx_lua_const_t) - 1;
    n += sizeof(ngx_lua_debug_methods) / sizeof(luaL_Reg) - 1;

    lua_createtable(lcf->l, 0, n);

    for (n = 0; ngx_lua_debug_consts[n].name != NULL; n++) {
        lua_pushinteger(lcf->l, ngx_lua_debug_consts[n].value);
        lua_setfield(lcf->l, -2, ngx_lua_debug_consts[n].name);
    }

    for (n = 0; ngx_lua_debug_methods[n].name != NULL; n++) {
        lua_pushcfunction(lcf->l, ngx_lua_debug_methods[n].func);
        lua_setfield(lcf->l, -2, ngx_lua_debug_methods[n].name);
    }

    lua_setfield(lcf->l, -2, "debug");

    lua_pop(lcf->l, 1);

    return NGX_OK;
}


static void *
ngx_lua_debug_create_conf(ngx_cycle_t *cycle)
{
    ngx_lua_debug_conf_t  *ldcf;

    ldcf = ngx_pcalloc(cycle->pool, sizeof(ngx_lua_debug_conf_t));
    if (ldcf == NULL) {
        return NULL;
    }

    ldcf->size = NGX_CONF_UNSET_SIZE;

    return ldcf;
}


static char *
ngx_lua_debug_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_lua_debug_conf_t *ldcf = conf;

    ldcf->event.handler = ngx_lua_debug_event;
    ldcf->event.data = ldcf;
    ldcf->event.log = cycle->log;

    return NGX_CONF_OK;
}


static char *
ngx_lua_debug(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_lua_debug_conf_t *ldcf = conf;

    ngx_str_t   *value, str;
    ngx_uint_t   i;

    if (ldcf->name.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "name=", 5) == 0) {
            ldcf->name.len = value[i].len - 5;
            ldcf->name.data = value[i].data + 5;
            continue;
        }

        if (ngx_strncmp(value[i].data, "size=", 5) == 0) {
            str.len = value[i].len - 5;
            str.data = value[i].data + 5;
            ldcf->size = ngx_parse_size(&str);
            if (ldcf->size == (size_t) NGX_ERROR) {
                goto invalid;
            }
            continue;
        }

        goto invalid;
    }

    if (ldcf->name.data == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the directive \"lua_debug\" must be specified");
        return NGX_CONF_ERROR;
    }

    ngx_conf_init_size_value(ldcf->size, 1024 * 1024 * 1);

    ldcf->zone = ngx_shared_memory_add(cf, &ldcf->name, ldcf->size,
                                       &ngx_lua_debug_module);
    if (ldcf->zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ldcf->zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate lua debug name \"%V\"", &ldcf->name);
        return NGX_CONF_ERROR;
    }

    ldcf->zone->init = ngx_lua_debug_init;
    ldcf->zone->data = ldcf;

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\" in lua_debug", &value[i]);

    return NGX_CONF_ERROR;
}
