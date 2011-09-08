
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_module.h>


static void ngx_lua_cache_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_lua_cache_code_t *ngx_lua_cache_lookup(ngx_lua_main_conf_t *lmcf,
    ngx_lua_ctx_t *ctx);


ngx_int_t
ngx_lua_cache_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_lua_main_conf_t *olmcf = data;

    size_t                len;
    ngx_lua_main_conf_t  *lmcf;

    lmcf = shm_zone->data;

    if (olmcf) {
        lmcf->cache = olmcf->cache;
        lmcf->cache_pool = olmcf->cache_pool;
        return NGX_OK;
    }

    lmcf->cache_pool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        lmcf->cache = lmcf->cache_pool->data;
        return NGX_OK;
    }

    lmcf->cache = ngx_slab_alloc(lmcf->cache_pool, sizeof(ngx_lua_cache_t));
    if (lmcf->cache == NULL) {
        return NGX_ERROR;
    }

    lmcf->cache_pool->data = lmcf->cache;

    ngx_rbtree_init(&lmcf->cache->rbtree, &lmcf->cache->sentinel,
                    ngx_lua_cache_insert_value);
    ngx_queue_init(&lmcf->cache->queue);

    len = sizeof(" in lua cache \"\"") + shm_zone->shm.name.len;

    lmcf->cache_pool->log_ctx = ngx_slab_alloc(lmcf->cache_pool, len);
    if (lmcf->cache_pool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(lmcf->cache_pool->log_ctx, " in lua cache \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


void
ngx_lua_cache_expire(ngx_event_t *ev)
{
    time_t                 now;
    ngx_uint_t             i;
    ngx_queue_t           *q;
    ngx_lua_main_conf_t   *lmcf;
    ngx_lua_cache_code_t  *code;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "lua cache expire");

    lmcf = ev->data;

    if (!ngx_shmtx_trylock(&lmcf->cache_pool->mutex)) {
        goto done;
    }

    now = ngx_time();

    for (i = 0; i < 2; i++) {
        if (ngx_queue_empty(&lmcf->cache->queue)) {
            break;
        }

        q = ngx_queue_last(&lmcf->cache->queue);
        code = ngx_queue_data(q, ngx_lua_cache_code_t, queue);

        if (code->expire >= now) {
            break;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                       "lua cache expire node \"%V\"", &code->path);

        ngx_queue_remove(&code->queue);
        ngx_rbtree_delete(&lmcf->cache->rbtree, &code->node);
        ngx_slab_free_locked(lmcf->cache_pool, code);
    }

    ngx_shmtx_unlock(&lmcf->cache_pool->mutex);

done:

    ngx_add_timer(&lmcf->cache_event, lmcf->cache_expire * 1000 / 10);
}


ngx_int_t
ngx_lua_cache_get(ngx_http_request_t *r, ngx_lua_ctx_t *ctx)
{
    time_t                 now;
    ngx_lua_main_conf_t   *lmcf;
    ngx_lua_cache_code_t  *code;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lua cache get");

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_module);

    ngx_shmtx_lock(&lmcf->cache_pool->mutex);

    code = ngx_lua_cache_lookup(lmcf, ctx);
    if (code == NULL) {
        ngx_shmtx_unlock(&lmcf->cache_pool->mutex);
        return NGX_DECLINED;
    }

    now = ngx_time();

    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "mtime:%T-%T size:%uz-%uz expire:%T-%T",
                   code->mtime, ctx->mtime, code->size, ctx->size, code->expire,
                   now);

    if (code->mtime != ctx->mtime
        || code->size != ctx->size
        || code->expire < now)
    {
        ngx_queue_remove(&code->queue);
        ngx_rbtree_delete(&lmcf->cache->rbtree, &code->node);
        ngx_slab_free_locked(lmcf->cache_pool, code);

        ngx_shmtx_unlock(&lmcf->cache_pool->mutex);
        return NGX_DECLINED;
    }

    ctx->buf->last = ngx_cpymem(ctx->buf->pos, code->code.data, code->code.len);

    ngx_queue_remove(&code->queue);
    code->expire = ngx_time() + lmcf->cache_expire + 60;
    ngx_queue_insert_head(&lmcf->cache->queue, &code->queue);

    ngx_shmtx_unlock(&lmcf->cache_pool->mutex);

    return NGX_OK;
}


ngx_int_t
ngx_lua_cache_set(ngx_http_request_t *r, ngx_lua_ctx_t *ctx)
{
    size_t                 size;
    u_char                *p;
    ngx_lua_main_conf_t   *lmcf;
    ngx_lua_cache_code_t  *code;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lua cache set");

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_module);

    ngx_shmtx_lock(&lmcf->cache_pool->mutex);

    code = ngx_lua_cache_lookup(lmcf, ctx);
    if (code != NULL) {
        ngx_queue_remove(&code->queue);
        code->expire = ngx_time() + lmcf->cache_expire + 60;
        ngx_queue_insert_head(&lmcf->cache->queue, &code->queue);

        ngx_shmtx_unlock(&lmcf->cache_pool->mutex);
        return NGX_OK;
    }

    size = ngx_align(sizeof(ngx_lua_cache_code_t), NGX_ALIGNMENT)
           + ngx_align(ctx->path.len, NGX_ALIGNMENT)
           + ngx_align(ctx->buf->last - ctx->buf->pos, NGX_ALIGNMENT);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua cache node size:%uz", size);

    p = ngx_slab_alloc_locked(lmcf->cache_pool, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "ngx_slab_alloc_locked() failed");
        ngx_shmtx_unlock(&lmcf->cache_pool->mutex);
        return NGX_ERROR;
    }

    code = (ngx_lua_cache_code_t *) p;
    p += ngx_align(sizeof(ngx_lua_cache_code_t), NGX_ALIGNMENT);

    ngx_memzero(code, sizeof(ngx_lua_cache_code_t));

    code->expire = ngx_time() + lmcf->cache_expire + 60;

    code->path.len = ctx->path.len;
    code->path.data = p;
    p += ngx_align(ctx->path.len, NGX_ALIGNMENT);
    ngx_memcpy(code->path.data, ctx->path.data, ctx->path.len);

    code->size = ctx->size;
    code->mtime = ctx->mtime;

    code->code.len = ctx->buf->last - ctx->buf->pos;
    code->code.data = p;
    ngx_memcpy(code->code.data, ctx->buf->pos, code->code.len);

    code->node.key = ngx_crc32_short(ctx->path.data, ctx->path.len);
    ngx_rbtree_insert(&lmcf->cache->rbtree, &code->node);
    ngx_queue_insert_head(&lmcf->cache->queue, &code->queue);

    ngx_shmtx_unlock(&lmcf->cache_pool->mutex);

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
ngx_lua_cache_lookup(ngx_lua_main_conf_t *lmcf, ngx_lua_ctx_t *ctx)
{
    ngx_int_t              rc;
    ngx_rbtree_key_t       key;
    ngx_rbtree_node_t     *node, *sentinel;
    ngx_lua_cache_code_t  *code;

    key = ngx_crc32_short(ctx->path.data, ctx->path.len);

    node = lmcf->cache->rbtree.root;
    sentinel = lmcf->cache->rbtree.sentinel;

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

            rc = ngx_memn2cmp(code->path.data, ctx->path.data, code->path.len,
                              ctx->path.len);

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
