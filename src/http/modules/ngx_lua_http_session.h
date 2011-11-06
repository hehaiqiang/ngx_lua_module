
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_LUA_SESSION_H_INCLUDED_
#define _NGX_LUA_SESSION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua.h>


typedef struct {
    ngx_rbtree_node_t          node;
    ngx_queue_t                queue;

    ngx_str_t                  name;
    ngx_str_t                  value;
} ngx_lua_session_var_node_t;


typedef struct {
    ngx_rbtree_node_t          node;
    ngx_queue_t                queue;

    ngx_rbtree_t               var_rbtree;
    ngx_rbtree_node_t          var_sentinel;
    ngx_queue_t                var_queue;

    u_char                     id[16];
} ngx_lua_session_node_t;


typedef struct {
    ngx_lua_session_node_t    *node;

    ngx_uint_t                 type;
    u_char                     id[16];

    uint32_t                   ip;
    in_port_t                  port;

    ngx_uint_t                 param;
    ngx_str_t                  param_val;
    ngx_str_t                  var_name;
    ngx_str_t                  var_val;

    ngx_uint_t                 result;
} ngx_lua_session_t;


ngx_int_t ngx_lua_session_create(ngx_lua_thread_t *thr, ngx_lua_session_t *s);
ngx_int_t ngx_lua_session_destroy(ngx_lua_thread_t *thr, ngx_lua_session_t *s);
ngx_int_t ngx_lua_session_set_param(ngx_lua_thread_t *thr,
    ngx_lua_session_t *s);
ngx_int_t ngx_lua_session_get_param(ngx_lua_thread_t *thr,
    ngx_lua_session_t *s);
ngx_int_t ngx_lua_session_set_var(ngx_lua_thread_t *thr, ngx_lua_session_t *s);
ngx_int_t ngx_lua_session_get_var(ngx_lua_thread_t *thr, ngx_lua_session_t *s);
ngx_int_t ngx_lua_session_del_var(ngx_lua_thread_t *thr, ngx_lua_session_t *s);


#endif /* _NGX_LUA_SESSION_H_INCLUDED_ */
