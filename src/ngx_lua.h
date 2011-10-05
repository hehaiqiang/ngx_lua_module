
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


typedef struct {
    char                   *name;
    int                     value;
} ngx_lua_const_t;


typedef struct {
    ngx_uint_t              index;
    void                   *handle;
    void                 *(*create_conf)(ngx_cycle_t *cycle);
    char                 *(*init_conf)(ngx_cycle_t *cycle, void *conf);
    char                 *(*set_directive)(ngx_conf_t *cf, ngx_command_t *cmd,
                                           void *conf);
    ngx_int_t             (*init_module)(ngx_cycle_t *cycle);
    ngx_int_t             (*init_process)(ngx_cycle_t *cycle);
    void                  (*exit_process)(ngx_cycle_t *cycle);
} ngx_lua_module_t;


typedef struct {
    ngx_str_t               path;
    ngx_str_t               cpath;
    lua_State              *l;
    void                  **conf;
} ngx_lua_conf_t;


typedef struct ngx_lua_thread_s  ngx_lua_thread_t;

typedef ngx_int_t (*ngx_lua_output_t)(ngx_lua_thread_t *thr, u_char *buf,
    size_t size);
typedef void (*ngx_lua_finalize_t)(ngx_lua_thread_t *thr, ngx_int_t rc);


struct ngx_lua_thread_s {
    ngx_pool_t             *pool;
    ngx_log_t              *log;
    ngx_file_t              file;
    ngx_str_t               path;
    size_t                  size;
    time_t                  mtime;
    ngx_buf_t              *lsp;
    ngx_buf_t              *buf;
    lua_State              *l;
    int                     ref;
    void                   *ctx;
    ngx_connection_t       *c;
    ngx_lua_output_t        output;
    ngx_lua_finalize_t      finalize;
    unsigned                cached:1;
};


ngx_int_t ngx_lua_create(ngx_cycle_t *cycle, ngx_lua_conf_t *lcf);
void ngx_lua_destroy(void *data);
void ngx_lua_thread_destroy(ngx_lua_thread_t *thr);
ngx_int_t ngx_lua_thread_run(ngx_lua_thread_t *thr, int n);
ngx_lua_thread_t *ngx_lua_thread(lua_State *l);
void ngx_lua_load(ngx_lua_thread_t *thr);

ngx_int_t ngx_lua_parse(ngx_lua_thread_t *thr);

ngx_int_t ngx_lua_cache_get(ngx_lua_thread_t *thr);
ngx_int_t ngx_lua_cache_set(ngx_lua_thread_t *thr);


#define ngx_lua_output(thr, buf, size)  thr->output(thr, buf, size)
#define ngx_lua_finalize(thr, rc)       thr->finalize(thr, rc)


#define ngx_lua_get_conf(cycle, module)                                       \
    ((ngx_lua_conf_t *)                                                       \
     ngx_get_conf(cycle->conf_ctx, ngx_lua_module))->conf[module.index]


extern ngx_module_t  ngx_lua_module;
extern ngx_uint_t    ngx_lua_max_module;


#endif /* _NGX_LUA_H_INCLUDED_ */