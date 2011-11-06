
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_http_module.h>


#define NGX_LUA_SESSION_MODE_SINGLE   1
#define NGX_LUA_SESSION_MODE_CLUSTER  2


#define NGX_LUA_SESSION_CREATE     1
#define NGX_LUA_SESSION_DESTROY    2
#define NGX_LUA_SESSION_SET_PARAM  3
#define NGX_LUA_SESSION_GET_PARAM  4
#define NGX_LUA_SESSION_SET_VAR    5
#define NGX_LUA_SESSION_GET_VAR    6
#define NGX_LUA_SESSION_DEL_VAR    7


typedef struct {
    ngx_rbtree_t              rbtree;
    ngx_rbtree_node_t         sentinel;
    ngx_queue_t               queue;
} ngx_lua_session_shm_t;


typedef struct {
    ngx_uint_t                mode;
    ngx_str_t                 server;
    ngx_str_t                 name;
    size_t                    size;

    ngx_lua_session_shm_t    *shm;
    ngx_slab_pool_t          *pool;
    ngx_shm_zone_t           *zone;
} ngx_lua_session_conf_t;


static void ngx_lua_session_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_lua_session_node_t *ngx_lua_session_lookup(ngx_lua_thread_t *thr,
    ngx_lua_session_t *s);

static void ngx_lua_session_var_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_lua_session_var_node_t *ngx_lua_session_var_lookup(
    ngx_lua_thread_t *thr, ngx_lua_session_t *s);

static ngx_int_t ngx_lua_session_init(ngx_shm_zone_t *shm_zone, void *data);

static void *ngx_lua_session_create_conf(ngx_cycle_t *cycle);
static char *ngx_lua_session_init_conf(ngx_cycle_t *cycle, void *conf);
static char *ngx_lua_session(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_lua_session_commands[] = {

    { ngx_string("lua_session"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE23,
      ngx_lua_session,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_lua_session_module_ctx = {
    ngx_string("session"),
    ngx_lua_session_create_conf,
    ngx_lua_session_init_conf,
};


ngx_module_t  ngx_lua_session_module = {
    NGX_MODULE_V1,
    &ngx_lua_session_module_ctx,           /* module context */
    ngx_lua_session_commands,              /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_lua_session_create(ngx_lua_thread_t *thr, ngx_lua_session_t *s)
{
    /* TODO */

    ngx_lua_session_lookup(thr, s);

    ngx_lua_session_var_insert_value(NULL, NULL, NULL);

    return NGX_OK;
}


ngx_int_t
ngx_lua_session_destroy(ngx_lua_thread_t *thr, ngx_lua_session_t *s)
{
    /* TODO */

    return NGX_OK;
}


ngx_int_t
ngx_lua_session_set_param(ngx_lua_thread_t *thr, ngx_lua_session_t *s)
{
    /* TODO */

    return NGX_OK;
}


ngx_int_t
ngx_lua_session_get_param(ngx_lua_thread_t *thr, ngx_lua_session_t *s)
{
    /* TODO */

    return NGX_OK;
}


ngx_int_t
ngx_lua_session_set_var(ngx_lua_thread_t *thr, ngx_lua_session_t *s)
{
    /* TODO */

    return NGX_OK;
}


ngx_int_t
ngx_lua_session_get_var(ngx_lua_thread_t *thr, ngx_lua_session_t *s)
{
    /* TODO */

    ngx_lua_session_var_lookup(thr, s);

    return NGX_OK;
}


ngx_int_t
ngx_lua_session_del_var(ngx_lua_thread_t *thr, ngx_lua_session_t *s)
{
    /* TODO */

    return NGX_OK;
}


static void
ngx_lua_session_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t       **p;
    ngx_lua_session_node_t   *sn, *snt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            sn = (ngx_lua_session_node_t *) node;
            snt = (ngx_lua_session_node_t *) temp;

            p = ngx_memcmp(sn->id, snt->id, sizeof(sn->id))
                < 0 ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_lua_session_node_t *
ngx_lua_session_lookup(ngx_lua_thread_t *thr, ngx_lua_session_t *s)
{
    ngx_int_t                rc;
    ngx_rbtree_key_t         key;
    ngx_rbtree_node_t       *node, *sentinel;
    ngx_lua_session_node_t  *sn;
    ngx_lua_session_conf_t  *lscf;

    lscf = ngx_lua_thread_get_conf(thr, ngx_lua_session_module);

    key = ngx_crc32_short(s->id, sizeof(s->id));

    node = lscf->shm->rbtree.root;
    sentinel = lscf->shm->rbtree.sentinel;

    while (node != sentinel) {

        if (key < node->key) {
            node = node->left;
            continue;
        }

        if (key > node->key) {
            node = node->right;
            continue;
        }

        /* key == node->key */

        do {
            sn = (ngx_lua_session_node_t *) node;

            rc = ngx_memcmp(s->id, sn->id, sizeof(s->id));

            if (rc == 0) {
                return sn;
            }

            node = (rc < 0) ? node->left : node->right;

        } while (node != sentinel && key == node->key);

        break;
    }

    /* not found */

    return NULL;
}


static void
ngx_lua_session_var_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t           **p;
    ngx_lua_session_var_node_t   *svn, *svnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            svn = (ngx_lua_session_var_node_t *) node;
            svnt = (ngx_lua_session_var_node_t *) temp;

            p = ngx_memn2cmp(svn->name.data, svnt->name.data, svn->name.len,
                             svnt->name.len)
                < 0 ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_lua_session_var_node_t *
ngx_lua_session_var_lookup(ngx_lua_thread_t *thr, ngx_lua_session_t *s)
{
    ngx_int_t                    rc;
    ngx_str_t                   *var;
    ngx_rbtree_key_t             key;
    ngx_rbtree_node_t           *node, *sentinel;
    ngx_lua_session_var_node_t  *svn;

    var = &s->var_name;

    key = ngx_crc32_short(var->data, var->len);

    node = s->node->var_rbtree.root;
    sentinel = s->node->var_rbtree.sentinel;

    while (node != sentinel) {

        if (key < node->key) {
            node = node->left;
            continue;
        }

        if (key > node->key) {
            node = node->right;
            continue;
        }

        /* key == node->key */

        do {
            svn = (ngx_lua_session_var_node_t *) node;

            rc = ngx_memn2cmp(var->data, svn->name.data, var->len,
                              svn->name.len);

            if (rc == 0) {
                return svn;
            }

            node = (rc < 0) ? node->left : node->right;

        } while (node != sentinel && key == node->key);

        break;
    }

    /* not found */

    return NULL;
}


static ngx_int_t
ngx_lua_session_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_lua_session_conf_t *olscf = data;

    size_t                   len;
    ngx_lua_session_conf_t  *lscf;

    lscf = shm_zone->data;

    if (olscf) {
        lscf->shm = olscf->shm;
        lscf->pool = olscf->pool;
        return NGX_OK;
    }

    lscf->pool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        lscf->shm = lscf->pool->data;
        return NGX_OK;
    }

    lscf->shm = ngx_slab_alloc(lscf->pool, sizeof(ngx_lua_session_shm_t));
    if (lscf->shm == NULL) {
        return NGX_ERROR;
    }

    lscf->pool->data = lscf->shm;

    ngx_rbtree_init(&lscf->shm->rbtree, &lscf->shm->sentinel,
                    ngx_lua_session_insert_value);
    ngx_queue_init(&lscf->shm->queue);

    len = sizeof(" in lua session \"\"") + shm_zone->shm.name.len;

    lscf->pool->log_ctx = ngx_slab_alloc(lscf->pool, len);
    if (lscf->pool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(lscf->pool->log_ctx, " in lua session \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


static void *
ngx_lua_session_create_conf(ngx_cycle_t *cycle)
{
    ngx_lua_session_conf_t  *lscf;

    lscf = ngx_pcalloc(cycle->pool, sizeof(ngx_lua_session_conf_t));
    if (lscf == NULL) {
        return NULL;
    }

    lscf->mode = NGX_CONF_UNSET_UINT;
    lscf->size = NGX_CONF_UNSET_SIZE;

    return lscf;
}


static char *
ngx_lua_session_init_conf(ngx_cycle_t *cycle, void *conf)
{
    /* TODO */

    return NGX_CONF_OK;
}


static char *
ngx_lua_session(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_lua_session_conf_t *lscf = conf;

    ngx_str_t   *value, str;
    ngx_uint_t   i;

    if (lscf->mode != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "mode=", 5) == 0) {
            str.len = value[i].len - 5;
            str.data = value[i].data + 5;

            if (ngx_strncmp(str.data, "single", 6) == 0) {
                lscf->mode = NGX_LUA_SESSION_MODE_SINGLE;

            } else if (ngx_strncmp(str.data, "cluster", 7) == 0) {
                lscf->mode = NGX_LUA_SESSION_MODE_CLUSTER;

            } else {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "server=", 7) == 0) {
            lscf->server.len = value[i].len - 7;
            lscf->server.data = value[i].data + 7;
            continue;
        }

        if (ngx_strncmp(value[i].data, "name=", 5) == 0) {
            lscf->name.len = value[i].len - 5;
            lscf->name.data = value[i].data + 5;
            continue;
        }

        if (ngx_strncmp(value[i].data, "size=", 5) == 0) {
            str.len = value[i].len - 5;
            str.data = value[i].data + 5;

            lscf->size = ngx_parse_size(&str);
            if (lscf->size == (size_t) NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        goto invalid;
    }

    if (lscf->mode == NGX_CONF_UNSET_UINT) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the directive \"lua_session\" must be specified");
        return NGX_CONF_ERROR;
    }

    if (lscf->mode == NGX_LUA_SESSION_MODE_SINGLE) {
        if (lscf->name.data == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the directive \"lua_session\" "
                               "must be specified");
            return NGX_CONF_ERROR;
        }

        ngx_conf_init_size_value(lscf->size, 1024 * 1024 * 1);

        lscf->zone = ngx_shared_memory_add(cf, &lscf->name, lscf->size,
                                           &ngx_lua_session_module);
        if (lscf->zone == NULL) {
            return NGX_CONF_ERROR;
        }

        if (lscf->zone->data) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate lua session name \"%V\"",
                               &lscf->name);
            return NGX_CONF_ERROR;
        }

        lscf->zone->init = ngx_lua_session_init;
        lscf->zone->data = lscf;

    } else {
        /* TODO: cluster */
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\" in lua_session", &value[i]);

    return NGX_CONF_ERROR;
}
