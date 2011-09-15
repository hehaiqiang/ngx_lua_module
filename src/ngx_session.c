
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_session.h>


static void ngx_session_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_session_node_t *ngx_session_lookup(ngx_session_t *s,
    ngx_session_ctx_t *ctx);

static void ngx_session_var_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_session_var_node_t *ngx_session_var_lookup(ngx_session_t *s,
    ngx_session_ctx_t *ctx);


ngx_int_t
ngx_session_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_session_t *os = data;

    size_t          len;
    ngx_session_t  *s;

    s = shm_zone->data;

    if (os) {
        s->shm = os->shm;
        s->pool = os->pool;
        return NGX_OK;
    }

    s->pool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        s->shm = s->pool->data;
        return NGX_OK;
    }

    s->shm = ngx_slab_alloc(s->pool, sizeof(ngx_session_shm_t));
    if (s->shm == NULL) {
        return NGX_ERROR;
    }

    s->pool->data = s->shm;

    ngx_rbtree_init(&s->shm->rbtree, &s->shm->sentinel,
                    ngx_session_insert_value);
    ngx_queue_init(&s->shm->queue);

    len = sizeof(" in lua session \"\"") + shm_zone->shm.name.len;

    s->pool->log_ctx = ngx_slab_alloc(s->pool, len);
    if (s->pool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(s->pool->log_ctx, " in lua session \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


ngx_int_t
ngx_session_create(ngx_session_t *s, ngx_session_ctx_t *ctx)
{
    /* TODO */

    ngx_session_lookup(s, ctx);

    ngx_session_var_insert_value(NULL, NULL, NULL);

    return NGX_OK;
}


ngx_int_t
ngx_session_destroy(ngx_session_t *s, ngx_session_ctx_t *ctx)
{
    /* TODO */

    return NGX_OK;
}


ngx_int_t
ngx_session_set_param(ngx_session_t *s, ngx_session_ctx_t *ctx)
{
    /* TODO */

    return NGX_OK;
}


ngx_int_t
ngx_session_get_param(ngx_session_t *s, ngx_session_ctx_t *ctx)
{
    /* TODO */

    return NGX_OK;
}


ngx_int_t
ngx_session_set_var(ngx_session_t *s, ngx_session_ctx_t *ctx)
{
    /* TODO */

    return NGX_OK;
}


ngx_int_t
ngx_session_get_var(ngx_session_t *s, ngx_session_ctx_t *ctx)
{
    /* TODO */

    ngx_session_var_lookup(s, ctx);

    return NGX_OK;
}


ngx_int_t
ngx_session_del_var(ngx_session_t *s, ngx_session_ctx_t *ctx)
{
    /* TODO */

    return NGX_OK;
}


static void
ngx_session_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t   **p;
    ngx_session_node_t   *sn, *snt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            sn = (ngx_session_node_t *) node;
            snt = (ngx_session_node_t *) temp;

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


static ngx_session_node_t *
ngx_session_lookup(ngx_session_t *s, ngx_session_ctx_t *ctx)
{
    ngx_int_t            rc;
    ngx_rbtree_key_t     key;
    ngx_rbtree_node_t   *node, *sentinel;
    ngx_session_node_t  *sn;

    key = ngx_crc32_short(ctx->id, sizeof(ctx->id));

    node = s->shm->rbtree.root;
    sentinel = s->shm->rbtree.sentinel;

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
            sn = (ngx_session_node_t *) node;

            rc = ngx_memcmp(ctx->id, sn->id, sizeof(ctx->id));

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
ngx_session_var_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t       **p;
    ngx_session_var_node_t   *svn, *svnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            svn = (ngx_session_var_node_t *) node;
            svnt = (ngx_session_var_node_t *) temp;

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


static ngx_session_var_node_t *
ngx_session_var_lookup(ngx_session_t *s, ngx_session_ctx_t *ctx)
{
    ngx_int_t                rc;
    ngx_str_t               *var;
    ngx_rbtree_key_t         key;
    ngx_rbtree_node_t       *node, *sentinel;
    ngx_session_var_node_t  *svn;

    var = &ctx->var_name;

    key = ngx_crc32_short(var->data, var->len);

    node = ctx->node->var_rbtree.root;
    sentinel = ctx->node->var_rbtree.sentinel;

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
            svn = (ngx_session_var_node_t *) node;

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
