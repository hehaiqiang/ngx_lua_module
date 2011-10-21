
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua.h>


typedef struct {
    ngx_rbtree_node_t     node;
    ngx_queue_t           queue;
    time_t                expire;
    ngx_str_t             path;
    size_t                size;
    time_t                mtime;
    ngx_str_t             code;
} ngx_lua_cache_code_t;


typedef struct {
    ngx_rbtree_t          rbtree;
    ngx_rbtree_node_t     sentinel;
    ngx_queue_t           queue;
} ngx_lua_cache_t;


typedef struct {
    ngx_str_t             name;
    size_t                size;
    time_t                expire;
    ngx_lua_cache_t      *cache;
    ngx_slab_pool_t      *pool;
    ngx_shm_zone_t       *zone;
    ngx_event_t           event;
} ngx_lua_cache_conf_t;


static void ngx_lua_cache_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_lua_cache_code_t *ngx_lua_cache_lookup(ngx_lua_cache_conf_t *lccf,
    ngx_lua_thread_t *thr);
static void ngx_lua_cache_expire(ngx_event_t *ev);
static ngx_int_t ngx_lua_cache_init(ngx_shm_zone_t *shm_zone, void *data);

static ngx_int_t ngx_lua_cache_process_init(ngx_cycle_t *cycle);
static void *ngx_lua_cache_create_conf(ngx_cycle_t *cycle);
static char *ngx_lua_cache_init_conf(ngx_cycle_t *cycle, void *conf);
static char *ngx_lua_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_lua_cache_commands[] = {

    { ngx_string("lua_cache"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE3,
      ngx_lua_cache,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_lua_cache_module_ctx = {
    ngx_string("cache"),
    ngx_lua_cache_create_conf,
    ngx_lua_cache_init_conf,
};


ngx_module_t  ngx_lua_cache_module = {
    NGX_MODULE_V1,
    &ngx_lua_cache_module_ctx,             /* module context */
    ngx_lua_cache_commands,                /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_lua_cache_process_init,            /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_lua_cache_get(ngx_lua_thread_t *thr)
{
    time_t                 now;
    ngx_lua_cache_conf_t  *lccf;
    ngx_lua_cache_code_t  *code;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua cache get");

    lccf = ngx_lua_thread_get_conf(thr, ngx_lua_cache_module);

    ngx_shmtx_lock(&lccf->pool->mutex);

    code = ngx_lua_cache_lookup(lccf, thr);
    if (code == NULL) {
        ngx_shmtx_unlock(&lccf->pool->mutex);
        return NGX_DECLINED;
    }

    now = ngx_time();

    ngx_log_debug6(NGX_LOG_DEBUG_CORE, thr->log, 0,
                   "mtime:%T-%T size:%uz-%uz expire:%T-%T",
                   code->mtime, thr->mtime, code->size, thr->size, code->expire,
                   now);

    if (code->mtime != thr->mtime
        || code->size != thr->size
        || code->expire < now)
    {
        ngx_queue_remove(&code->queue);
        ngx_rbtree_delete(&lccf->cache->rbtree, &code->node);
        ngx_slab_free_locked(lccf->pool, code);

        ngx_shmtx_unlock(&lccf->pool->mutex);
        return NGX_DECLINED;
    }

    thr->buf->last = ngx_cpymem(thr->buf->pos, code->code.data, code->code.len);

    ngx_queue_remove(&code->queue);
    code->expire = ngx_time() + lccf->expire + 60;
    ngx_queue_insert_head(&lccf->cache->queue, &code->queue);

    ngx_shmtx_unlock(&lccf->pool->mutex);

    return NGX_OK;
}


ngx_int_t
ngx_lua_cache_set(ngx_lua_thread_t *thr)
{
    size_t                 size;
    u_char                *p;
    ngx_lua_cache_conf_t  *lccf;
    ngx_lua_cache_code_t  *code;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua cache set");

    lccf = ngx_lua_thread_get_conf(thr, ngx_lua_cache_module);

    ngx_shmtx_lock(&lccf->pool->mutex);

    code = ngx_lua_cache_lookup(lccf, thr);
    if (code != NULL) {
        ngx_queue_remove(&code->queue);
        code->expire = ngx_time() + lccf->expire + 60;
        ngx_queue_insert_head(&lccf->cache->queue, &code->queue);

        ngx_shmtx_unlock(&lccf->pool->mutex);
        return NGX_OK;
    }

    size = ngx_align(sizeof(ngx_lua_cache_code_t), NGX_ALIGNMENT)
           + ngx_align(thr->path.len, NGX_ALIGNMENT)
           + ngx_align(thr->buf->last - thr->buf->pos, NGX_ALIGNMENT);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, thr->log, 0,
                   "lua cache node size:%uz", size);

    p = ngx_slab_alloc_locked(lccf->pool, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ALERT, thr->log, 0,
                      "ngx_slab_alloc_locked() failed");
        ngx_shmtx_unlock(&lccf->pool->mutex);
        return NGX_ERROR;
    }

    code = (ngx_lua_cache_code_t *) p;
    p += ngx_align(sizeof(ngx_lua_cache_code_t), NGX_ALIGNMENT);

    ngx_memzero(code, sizeof(ngx_lua_cache_code_t));

    code->expire = ngx_time() + lccf->expire + 60;

    code->path.len = thr->path.len;
    code->path.data = p;
    p += ngx_align(thr->path.len, NGX_ALIGNMENT);
    ngx_memcpy(code->path.data, thr->path.data, thr->path.len);

    code->size = thr->size;
    code->mtime = thr->mtime;

    code->code.len = thr->buf->last - thr->buf->pos;
    code->code.data = p;
    ngx_memcpy(code->code.data, thr->buf->pos, code->code.len);

    code->node.key = ngx_crc32_short(thr->path.data, thr->path.len);
    ngx_rbtree_insert(&lccf->cache->rbtree, &code->node);
    ngx_queue_insert_head(&lccf->cache->queue, &code->queue);

    ngx_shmtx_unlock(&lccf->pool->mutex);

    return NGX_OK;
}


static void
ngx_lua_cache_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t     **p;
    ngx_lua_cache_code_t   *code, *code_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            code = (ngx_lua_cache_code_t *) node;
            code_temp = (ngx_lua_cache_code_t *) temp;

            p = ngx_memn2cmp(code->path.data, code_temp->path.data,
                             code->path.len, code_temp->path.len)
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


static ngx_lua_cache_code_t *
ngx_lua_cache_lookup(ngx_lua_cache_conf_t *lccf, ngx_lua_thread_t *thr)
{
    ngx_int_t              rc;
    ngx_rbtree_key_t       key;
    ngx_rbtree_node_t     *node, *sentinel;
    ngx_lua_cache_code_t  *code;

    key = ngx_crc32_short(thr->path.data, thr->path.len);

    node = lccf->cache->rbtree.root;
    sentinel = lccf->cache->rbtree.sentinel;

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
            code = (ngx_lua_cache_code_t *) node;

            rc = ngx_memn2cmp(code->path.data, thr->path.data, code->path.len,
                              thr->path.len);

            if (rc == 0) {
                return code;
            }

            node = (rc < 0) ? node->left : node->right;

        } while (node != sentinel && key == node->key);

        break;
    }

    /* not found */

    return NULL;
}


static void
ngx_lua_cache_expire(ngx_event_t *ev)
{
    time_t                 now;
    ngx_uint_t             i;
    ngx_queue_t           *q;
    ngx_lua_cache_conf_t  *lccf;
    ngx_lua_cache_code_t  *code;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "lua cache expire");

    lccf = ev->data;

    if (!ngx_shmtx_trylock(&lccf->pool->mutex)) {
        goto done;
    }

    now = ngx_time();

    for (i = 0; i < 2; i++) {
        if (ngx_queue_empty(&lccf->cache->queue)) {
            break;
        }

        q = ngx_queue_last(&lccf->cache->queue);
        code = ngx_queue_data(q, ngx_lua_cache_code_t, queue);

        if (code->expire >= now) {
            break;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,
                       "lua cache expire node \"%V\"", &code->path);

        ngx_queue_remove(&code->queue);
        ngx_rbtree_delete(&lccf->cache->rbtree, &code->node);
        ngx_slab_free_locked(lccf->pool, code);
    }

    ngx_shmtx_unlock(&lccf->pool->mutex);

done:

    ngx_add_timer(&lccf->event, lccf->expire * 1000 / 10);
}


static ngx_int_t
ngx_lua_cache_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_lua_cache_conf_t *olccf = data;

    size_t                 len;
    ngx_lua_cache_conf_t  *lccf;

    lccf = shm_zone->data;

    if (olccf) {
        lccf->cache = olccf->cache;
        lccf->pool = olccf->pool;
        return NGX_OK;
    }

    lccf->pool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        lccf->cache = lccf->pool->data;
        return NGX_OK;
    }

    lccf->cache = ngx_slab_alloc(lccf->pool, sizeof(ngx_lua_cache_t));
    if (lccf->cache == NULL) {
        return NGX_ERROR;
    }

    lccf->pool->data = lccf->cache;

    ngx_rbtree_init(&lccf->cache->rbtree, &lccf->cache->sentinel,
                    ngx_lua_cache_insert_value);
    ngx_queue_init(&lccf->cache->queue);

    len = sizeof(" in lua cache \"\"") + shm_zone->shm.name.len;

    lccf->pool->log_ctx = ngx_slab_alloc(lccf->pool, len);
    if (lccf->pool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(lccf->pool->log_ctx, " in lua cache \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


static ngx_int_t
ngx_lua_cache_process_init(ngx_cycle_t *cycle)
{
    ngx_lua_cache_conf_t  *lccf;

    lccf = ngx_lua_get_conf(cycle, ngx_lua_cache_module);

    lccf->event.handler = ngx_lua_cache_expire;
    lccf->event.data = lccf;
    lccf->event.log = cycle->log;

    ngx_add_timer(&lccf->event, lccf->expire * 1000 / 10);

    return NGX_OK;
}


static void *
ngx_lua_cache_create_conf(ngx_cycle_t *cycle)
{
    ngx_lua_cache_conf_t  *lccf;

    lccf = ngx_pcalloc(cycle->pool, sizeof(ngx_lua_cache_conf_t));
    if (lccf == NULL) {
        return NULL;
    }

    lccf->size = NGX_CONF_UNSET_SIZE;
    lccf->expire = NGX_CONF_UNSET;

    return lccf;
}


static char *
ngx_lua_cache_init_conf(ngx_cycle_t *cycle, void *conf)
{
    /* TODO */

    return NGX_CONF_OK;
}


static char *
ngx_lua_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_lua_cache_conf_t *lccf = conf;

    ngx_str_t   *value, str;
    ngx_uint_t   i;

    if (lccf->name.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "name=", 5) == 0) {
            lccf->name.len = value[i].len - 5;
            lccf->name.data = value[i].data + 5;
            continue;
        }

        if (ngx_strncmp(value[i].data, "size=", 5) == 0) {
            str.len = value[i].len - 5;
            str.data = value[i].data + 5;
            lccf->size = ngx_parse_size(&str);
            if (lccf->size == (size_t) NGX_ERROR) {
                goto invalid;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "expire=", 7) == 0) {
            str.len = value[i].len - 7;
            str.data = value[i].data + 7;
            lccf->expire = ngx_parse_time(&str, 1);
            if (lccf->expire == NGX_ERROR) {
                goto invalid;
            }
            continue;
        }

        goto invalid;
    }

    if (lccf->name.data == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the directive \"lua_cache\" must be specified");
        return NGX_CONF_ERROR;
    }

    ngx_conf_init_size_value(lccf->size, 1024 * 1024 * 1);
    ngx_conf_init_value(lccf->expire, 30 * 60);

    lccf->zone = ngx_shared_memory_add(cf, &lccf->name, lccf->size,
                                       &ngx_lua_module);
    if (lccf->zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (lccf->zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate lua cache name \"%V\"",
                           &lccf->name);
        return NGX_CONF_ERROR;
    }

    lccf->zone->init = ngx_lua_cache_init;
    lccf->zone->data = lccf;

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\" in lua_cache", &value[i]);

    return NGX_CONF_ERROR;
}
