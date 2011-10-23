
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_axis2c.h>


typedef struct {
    axutil_allocator_t     allocator;
    ngx_lua_thread_t      *thr;
} ngx_lua_axis2c_allocator_t;


typedef struct {
    axutil_log_t           log;
    ngx_lua_thread_t      *thr;
} ngx_lua_axis2c_log_t;


static void *ngx_stdcall ngx_lua_axis2c_allocator_malloc(
    axutil_allocator_t *allocator, size_t size);
static void *ngx_stdcall ngx_lua_axis2c_allocator_realloc(
    axutil_allocator_t *allocator, void *ptr, size_t size);
static void ngx_stdcall ngx_lua_axis2c_allocator_free(
    axutil_allocator_t *allocator, void *ptr);

static void ngx_stdcall ngx_lua_axis2c_log_free(axutil_allocator_t *allocator,
    axutil_log_t *log);
static void ngx_stdcall ngx_lua_axis2c_log_write(axutil_log_t *log,
    const axis2_char_t *buffer, axutil_log_levels_t level,
    const axis2_char_t *file, const int line);


static axutil_log_ops_t  ngx_lua_axis2c_log_ops = {
    ngx_lua_axis2c_log_free,
    ngx_lua_axis2c_log_write
};


extern ngx_module_t  ngx_lua_webservice_module;
extern ngx_module_t  ngx_lua_xml_module;


#if (NGX_LUA_DLL)
ngx_module_t **
ngx_lua_get_modules(void)
{
    static ngx_module_t  *modules[] = {
        &ngx_lua_webservice_module,
        &ngx_lua_xml_module,
        NULL
    };

    return modules;
}
#endif


axutil_allocator_t *
ngx_lua_axis2c_allocator_create(ngx_lua_thread_t *thr)
{
    ngx_lua_axis2c_allocator_t  *a;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0,
                   "lua axis2c allocator create");

    a = ngx_pcalloc(thr->pool, sizeof(ngx_lua_axis2c_allocator_t));
    if (a == NULL) {
        return NULL;
    }

    a->allocator.malloc_fn = ngx_lua_axis2c_allocator_malloc;
    a->allocator.realloc = ngx_lua_axis2c_allocator_realloc;
    a->allocator.free_fn = ngx_lua_axis2c_allocator_free;
    a->thr = thr;

    return &a->allocator;
}


static void *ngx_stdcall
ngx_lua_axis2c_allocator_malloc(axutil_allocator_t *allocator, size_t size)
{
    ngx_lua_axis2c_allocator_t *a = (ngx_lua_axis2c_allocator_t *) allocator;

    u_char            *p;
    ngx_lua_thread_t  *thr;

    thr = a->thr;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0,
                   "lua axis2c allocator malloc");

    p = ngx_palloc(thr->pool, size + sizeof(size_t));
    if (p == NULL) {
        return NULL;
    }

    *((size_t *) p) = size;
    p += sizeof(size_t);

    return p;
}


static void *ngx_stdcall
ngx_lua_axis2c_allocator_realloc(axutil_allocator_t *allocator, void *ptr,
    size_t size)
{
    ngx_lua_axis2c_allocator_t *a = (ngx_lua_axis2c_allocator_t *) allocator;

    size_t             osize;
    u_char            *p;
    ngx_lua_thread_t  *thr;

    thr = a->thr;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0,
                   "lua axis2c allocator realloc");

    p = (u_char *) ptr - sizeof(size_t);
    osize = *((size_t *) p);

    if (osize >= size) {
        return ptr;
    }

    p = ngx_lua_axis2c_allocator_malloc(allocator, size);
    ngx_memcpy(p, ptr, osize);
    ngx_lua_axis2c_allocator_free(allocator, ptr);

    return p;
}


static void ngx_stdcall
ngx_lua_axis2c_allocator_free(axutil_allocator_t *allocator, void *ptr)
{
    ngx_lua_axis2c_allocator_t *a = (ngx_lua_axis2c_allocator_t *) allocator;

    size_t             size;
    u_char            *p;
    ngx_lua_thread_t  *thr;

    thr = a->thr;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0,
                   "lua axis2c allocator free");

    p = (u_char *) ptr - sizeof(size_t);
    size = *((size_t *) p) + sizeof(size_t);

    if (size > thr->pool->max) {
        ngx_pfree(thr->pool, p);
    }
}


axutil_log_t *
ngx_lua_axis2c_log_create(ngx_lua_thread_t *thr)
{
    ngx_lua_axis2c_log_t  *log;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua axis2c log create");

    log = ngx_pcalloc(thr->pool, sizeof(ngx_lua_axis2c_log_t));
    if (log == NULL) {
        return NULL;
    }

    log->log.ops = &ngx_lua_axis2c_log_ops;
    log->log.level = AXIS2_LOG_LEVEL_TRACE;
    log->log.enabled = 1;
    log->thr = thr;

    return &log->log;
}


static void ngx_stdcall
ngx_lua_axis2c_log_free(axutil_allocator_t *allocator, axutil_log_t *log)
{
}


static void ngx_stdcall
ngx_lua_axis2c_log_write(axutil_log_t *log, const axis2_char_t *buffer,
    axutil_log_levels_t level, const axis2_char_t *file, const int line)
{
    ngx_lua_axis2c_log_t *l = (ngx_lua_axis2c_log_t *) log;

    ngx_uint_t  log_level;

    switch (level) {
    case AXIS2_LOG_LEVEL_CRITICAL:
        log_level = NGX_LOG_CRIT;
        break;
    case AXIS2_LOG_LEVEL_ERROR:
        log_level = NGX_LOG_ERR;
        break;
    case AXIS2_LOG_LEVEL_WARNING:
        log_level = NGX_LOG_WARN;
        break;
    case AXIS2_LOG_LEVEL_INFO:
        log_level = NGX_LOG_INFO;
        break;
    case AXIS2_LOG_LEVEL_DEBUG:
    case AXIS2_LOG_LEVEL_USER:
    case AXIS2_LOG_LEVEL_TRACE:
        log_level = NGX_LOG_DEBUG;
        break;
    default:
        log_level = NGX_LOG_ALERT;
        break;
    }

    ngx_log_error(log_level, l->thr->log, 0, buffer);
}
