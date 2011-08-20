
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_module.h>


static void ngx_lua_cache_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_lua_code_t *ngx_lua_cache_lookup(ngx_lua_main_conf_t *lmcf,
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
        lmcf->pool = olmcf->pool;
        return NGX_OK;
    }

    lmcf->pool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        lmcf->cache = lmcf->pool->data;
        return NGX_OK;
    }

    lmcf->cache = ngx_slab_alloc(lmcf->pool, sizeof(ngx_lua_cache_t));
    if (lmcf->cache == NULL) {
        return NGX_ERROR;
    }

    lmcf->pool->data = lmcf->cache;

    ngx_rbtree_init(&lmcf->cache->rbtree, &lmcf->cache->sentinel,
                    ngx_lua_cache_insert_value);
    ngx_queue_init(&lmcf->cache->queue);

    len = sizeof(" in lua cache \"\"") + shm_zone->shm.name.len;

    lmcf->pool->log_ctx = ngx_slab_alloc(lmcf->pool, len);
    if (lmcf->pool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(lmcf->pool->log_ctx, " in lua cache \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


ngx_int_t
ngx_lua_cache_get(ngx_http_request_t *r, ngx_lua_ctx_t *ctx)
{
    ngx_lua_code_t       *lc;
    ngx_lua_main_conf_t  *lmcf;

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_module);

    ngx_shmtx_lock(&lmcf->pool->mutex);

    lc = ngx_lua_cache_lookup(lmcf, ctx);
    if (lc == NULL) {
        ngx_shmtx_unlock(&lmcf->pool->mutex);
        return NGX_DECLINED;
    }

    if (lc->mtime != ctx->mtime
        || lc->size != ctx->size
        || lc->expire < ngx_time())
    {
        ngx_queue_remove(&lc->queue);
        ngx_rbtree_delete(&lmcf->cache->rbtree, &lc->node);

        ngx_slab_free_locked(lmcf->pool, lc);

        ngx_shmtx_unlock(&lmcf->pool->mutex);

        return NGX_DECLINED;
    }

    ctx->buf->last = ngx_cpymem(ctx->buf->pos, lc->code.data, lc->code.len);

    ngx_queue_remove(&lc->queue);
    lc->expire = ngx_time() + lmcf->cache_expire + 60;
    ngx_queue_insert_head(&lmcf->cache->queue, &lc->queue);

    ngx_shmtx_unlock(&lmcf->pool->mutex);

    return NGX_OK;
}


ngx_int_t
ngx_lua_cache_set(ngx_http_request_t *r, ngx_lua_ctx_t *ctx)
{
    size_t                size;
    u_char               *p;
    ngx_lua_code_t       *lc;
    ngx_lua_main_conf_t  *lmcf;

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_module);

    ngx_shmtx_lock(&lmcf->pool->mutex);

    lc = ngx_lua_cache_lookup(lmcf, ctx);
    if (lc != NULL) {
        ngx_queue_remove(&lc->queue);
        lc->expire = ngx_time() + lmcf->cache_expire + 60;
        ngx_queue_insert_head(&lmcf->cache->queue, &lc->queue);

        ngx_shmtx_unlock(&lmcf->pool->mutex);

        return NGX_OK;
    }

    size = sizeof(ngx_lua_code_t) + ctx->path.len
           + ctx->buf->last - ctx->buf->pos;

    p = ngx_slab_alloc_locked(lmcf->pool, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "ngx_slab_alloc_locked() failed");
        ngx_shmtx_unlock(&lmcf->pool->mutex);
        return NGX_ERROR;
    }

    lc = (ngx_lua_code_t *) p;

    ngx_memzero(lc, sizeof(ngx_lua_code_t));

    lc->expire = ngx_time() + lmcf->cache_expire + 60;

    lc->path.len = ctx->path.len;
    lc->path.data = p + sizeof(ngx_lua_code_t);
    ngx_memcpy(lc->path.data, ctx->path.data, ctx->path.len);

    lc->size = ctx->size;
    lc->mtime = ctx->mtime;

    lc->code.len = ctx->buf->last - ctx->buf->pos;
    lc->code.data = p + sizeof(ngx_lua_code_t) + ctx->path.len;
    ngx_memcpy(lc->code.data, ctx->buf->pos, lc->code.len);

    lc->node.key = ngx_crc32_short(ctx->path.data, ctx->path.len);
    ngx_rbtree_insert(&lmcf->cache->rbtree, &lc->node);
    ngx_queue_insert_head(&lmcf->cache->queue, &lc->queue);

    ngx_shmtx_unlock(&lmcf->pool->mutex);

    return NGX_OK;
}


void
ngx_lua_cache_expire(ngx_lua_main_conf_t *lmcf)
{
#if 0
    time_t                 now;
    ngx_uint_t             i;
    ngx_queue_t           *q;
    ngx_p2p_cam_t         *pc;
    ngx_p2p_online_id_t   *poi;
    ngx_p2p_online_cam_t  *poc;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "p2p expire nodes");

    /* expire cameras */

    ngx_shmtx_lock(&p2p->shpool->mutex);

    now = ngx_time();

    for (i = 0; i < 2; i++) {
        if (ngx_queue_empty(&p2p->sh->cam_queue)) {
            break;
        }

        q = ngx_queue_last(&p2p->sh->cam_queue);
        pc = ngx_queue_data(q, ngx_p2p_cam_t, queue);

        if (now <= pc->expire) {
            break;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                       "p2p camera expire \"%s\"", pc->camera_id);

        ngx_queue_remove(&pc->queue);
        ngx_rbtree_delete(&p2p->sh->cam_rbtree, &pc->node);
        ngx_slab_free_locked(p2p->shpool, pc);

        ngx_atomic_fetch_add(&p2p->sh->cam_count, -1);
    }

    ngx_shmtx_unlock(&p2p->shpool->mutex);
#endif
}


static void
ngx_lua_cache_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_lua_code_t      *lc, *lct;
    ngx_rbtree_node_t  **p;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lc = (ngx_lua_code_t *) node;
            lct = (ngx_lua_code_t *) temp;

            p = ngx_memn2cmp(lc->path.data, lct->path.data, lc->path.len,
                             lct->path.len)
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


static ngx_lua_code_t *
ngx_lua_cache_lookup(ngx_lua_main_conf_t *lmcf, ngx_lua_ctx_t *ctx)
{
    ngx_int_t           rc;
    ngx_lua_code_t     *lc;
    ngx_rbtree_key_t    key;
    ngx_rbtree_node_t  *node, *sentinel;

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
            lc = (ngx_lua_code_t *) node;

            rc = ngx_memn2cmp(lc->path.data, ctx->path.data, lc->path.len,
                              ctx->path.len);

            if (rc == 0) {
                return lc;
            }

            node = (rc < 0) ? node->left : node->right;

        } while (node != sentinel && key == node->key);

        break;
    }

    /* not found */

    return NULL;
}
