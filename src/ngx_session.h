
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_SESSION_H_INCLUDED_
#define _NGX_SESSION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_SESSION_MODE_SINGLE   1
#define NGX_SESSION_MODE_CLUSTER  2


#define NGX_SESSION_CREATE     1
#define NGX_SESSION_DESTROY    2
#define NGX_SESSION_SET_PARAM  3
#define NGX_SESSION_GET_PARAM  4
#define NGX_SESSION_SET_VAR    5
#define NGX_SESSION_GET_VAR    6
#define NGX_SESSION_DEL_VAR    7


typedef struct {
    ngx_rbtree_node_t      node;
    ngx_queue_t            queue;

    ngx_str_t              name;
    ngx_str_t              value;
} ngx_session_var_node_t;


typedef struct {
    ngx_rbtree_node_t      node;
    ngx_queue_t            queue;

    ngx_rbtree_t           var_rbtree;
    ngx_rbtree_node_t      var_sentinel;
    ngx_queue_t            var_queue;

    u_char                 id[16];
} ngx_session_node_t;


typedef struct {
    ngx_rbtree_t           rbtree;
    ngx_rbtree_node_t      sentinel;
    ngx_queue_t            queue;
} ngx_session_shm_t;


typedef struct {
    ngx_session_shm_t     *shm;
    ngx_slab_pool_t       *pool;
} ngx_session_t;


typedef struct {
    ngx_session_node_t    *node;

    ngx_uint_t             type;
    u_char                 id[16];

    uint32_t               ip;
    in_port_t              port;

    ngx_uint_t             param;
    ngx_str_t              param_val;
    ngx_str_t              var_name;
    ngx_str_t              var_val;

    ngx_uint_t             result;
} ngx_session_ctx_t;


ngx_int_t ngx_session_init(ngx_shm_zone_t *shm_zone, void *data);

ngx_int_t ngx_session_create(ngx_session_t *s, ngx_session_ctx_t *ctx);
ngx_int_t ngx_session_destroy(ngx_session_t *s, ngx_session_ctx_t *ctx);
ngx_int_t ngx_session_set_param(ngx_session_t *s, ngx_session_ctx_t *ctx);
ngx_int_t ngx_session_get_param(ngx_session_t *s, ngx_session_ctx_t *ctx);
ngx_int_t ngx_session_set_var(ngx_session_t *s, ngx_session_ctx_t *ctx);
ngx_int_t ngx_session_get_var(ngx_session_t *s, ngx_session_ctx_t *ctx);
ngx_int_t ngx_session_del_var(ngx_session_t *s, ngx_session_ctx_t *ctx);


#endif /* _NGX_SESSION_H_INCLUDED_ */
