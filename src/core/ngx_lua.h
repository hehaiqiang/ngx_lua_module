
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_LUA_H_INCLUDED_
#define _NGX_LUA_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>


#define NGX_LUA_TABLE  "nginx"


#define NGX_LUA_SCRIPT_FROM_CONF  1
#define NGX_LUA_SCRIPT_FROM_FILE  2


typedef struct {
    ngx_str_t                path;
    ngx_str_t                cpath;
    lua_State               *l;
    void                   **handle;
    void                   **conf;
} ngx_lua_conf_t;


typedef struct {
    char                    *name;
    int                      value;
} ngx_lua_const_t;


typedef struct ngx_lua_thread_s  ngx_lua_thread_t;

typedef ngx_int_t (*ngx_lua_parser_pt)(ngx_lua_thread_t *thr);
typedef ngx_int_t (*ngx_lua_output_pt)(ngx_lua_thread_t *thr, u_char *buf,
    size_t size);
typedef void (*ngx_lua_finalize_pt)(ngx_lua_thread_t *thr, ngx_int_t rc);


typedef struct {
    ngx_str_t                name;
    ngx_lua_parser_pt        parser;
} ngx_lua_parser_t;


typedef struct {
    ngx_uint_t               from;
    ngx_str_t                path;
    ngx_str_t                code;
    ngx_lua_parser_pt        parser;
} ngx_lua_script_t;


struct ngx_lua_thread_s {
    ngx_pool_t              *pool;
    ngx_log_t               *log;
    ngx_file_t               file;
    ngx_str_t                path;
    size_t                   size;
    time_t                   mtime;
    ngx_buf_t               *lsp;
    ngx_buf_t               *buf;
    lua_State               *l;
    int                      ref;
    void                   **conf;
    void                    *ctx;
    ngx_connection_t        *c;
    ngx_lua_script_t        *script;
    ngx_lua_output_pt        output;
    ngx_lua_finalize_pt      finalize;
    unsigned                 cached:1;
};


ngx_int_t ngx_lua_create(ngx_cycle_t *cycle, ngx_lua_conf_t *lcf);
void ngx_lua_destroy(void *data);
ngx_int_t ngx_lua_thread_create(ngx_lua_thread_t *thr);
void ngx_lua_thread_destroy(ngx_lua_thread_t *thr);
ngx_int_t ngx_lua_thread_run(ngx_lua_thread_t *thr, int n);
ngx_lua_thread_t *ngx_lua_thread(lua_State *l);
ngx_int_t ngx_lua_check_script(ngx_lua_thread_t *thr);
void ngx_lua_load_script(ngx_lua_thread_t *thr);

ngx_int_t ngx_lua_cache_get(ngx_lua_thread_t *thr);
ngx_int_t ngx_lua_cache_set(ngx_lua_thread_t *thr);

ngx_lua_parser_pt ngx_lua_parser_find(ngx_log_t *log, ngx_str_t *name);

char *ngx_lua_set_script_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_lua_set_script_parser_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


#define ngx_lua_output(thr, buf, size)  thr->output(thr, buf, size)
#define ngx_lua_finalize(thr, rc)       thr->finalize(thr, rc)


#define ngx_lua_get_conf(cycle, module)                                       \
    ((ngx_lua_conf_t *)                                                       \
     ngx_get_conf(cycle->conf_ctx, ngx_lua_module))->conf[module.index]

#define ngx_lua_thread_get_conf(thr, module)  (thr)->conf[module.index]


#if !(NGX_WIN32)

#include <dlfcn.h>

#define ngx_lua_dlopen(name)        dlopen(name, RTLD_LAZY)
#define ngx_lua_dlopen_n            "dlopen()"

#define ngx_lua_dlclose(handle)     dlclose(handle)

#define ngx_lua_dlsym(handle, sym)  dlsym(handle, sym)
#define ngx_lua_dlsym_n             "dlsym()"

#define ngx_lua_dlerror()           dlerror()

#else

#define ngx_lua_dlopen(name)        LoadLibrary(name)
#define ngx_lua_dlopen_n            "LoadLibrary()"

#define ngx_lua_dlclose(handle)     FreeLibrary(handle)

#define ngx_lua_dlsym(handle, sym)  GetProcAddress(handle, sym)
#define ngx_lua_dlsym_n             "GetProcAddress()"

#define ngx_lua_dlerror()           ""

#endif


extern ngx_dll ngx_module_t   ngx_lua_module;
extern ngx_module_t          *ngx_lua_modules[];
extern ngx_uint_t             ngx_lua_max_module;


#endif /* _NGX_LUA_H_INCLUDED_ */