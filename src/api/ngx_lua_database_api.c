
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_dbd.h>
#include <ngx_lua_module.h>


typedef struct {
    ngx_queue_t                   queue;
    ngx_str_t                     name;
    ngx_pool_t                   *pool;
    ngx_dbd_t                    *dbd;
    ngx_uint_t                    connected;
} ngx_lua_dbd_connection_t;


typedef struct {
    ngx_rbtree_node_t             node;
    ngx_str_t                     name;
    ngx_queue_t                   connections;
    ngx_uint_t                    connection_n;
    ngx_queue_t                   free_connections;
    ngx_uint_t                    free_connection_n;
} ngx_lua_dbd_pool_t;


typedef struct ngx_lua_dbd_cleanup_ctx_s  ngx_lua_dbd_cleanup_ctx_t;


typedef struct {
    ngx_pool_t                   *pool;
    ngx_lua_main_conf_t          *lmcf;
    ngx_lua_dbd_connection_t     *c;
    uint64_t                      row_count;
    uint64_t                      col_count;
    ngx_int_t                     rc;
    ngx_uint_t                    not_event;
    ngx_http_request_t           *r;
    ngx_lua_dbd_cleanup_ctx_t    *cln_ctx;
} ngx_lua_dbd_ctx_t;


struct ngx_lua_dbd_cleanup_ctx_s {
    ngx_lua_dbd_ctx_t            *ctx;
};


static int ngx_lua_dbd_create_pool(lua_State *l);
static int ngx_lua_dbd_destroy_pool(lua_State *l);
static void ngx_lua_dbd_pool_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_lua_dbd_conf_t *ngx_lua_dbd_pool_lookup(ngx_lua_main_conf_t *lmcf,
    ngx_str_t *name);

static int ngx_lua_dbd_execute(lua_State *l);

static ngx_lua_dbd_connection_t *ngx_lua_dbd_get_connection(
    ngx_http_request_t *r, ngx_str_t *name);
static void ngx_lua_dbd_free_connection(ngx_lua_main_conf_t *lmcf,
    ngx_lua_dbd_connection_t *c);
static void ngx_lua_dbd_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_lua_dbd_pool_t *ngx_lua_dbd_lookup(ngx_lua_main_conf_t *lmcf,
    ngx_str_t *name);

static void ngx_lua_dbd_connect(void *data);
static void ngx_lua_dbd_query(void *data);
static void ngx_lua_dbd_column(void *data);
static void ngx_lua_dbd_row(void *data);
static void ngx_lua_dbd_field(void *data);

static void ngx_lua_dbd_finalize(ngx_lua_dbd_ctx_t *ctx, ngx_int_t rc);
static void ngx_lua_dbd_cleanup(void *data);


static luaL_Reg  ngx_lua_dbd_methods[] = {
    { "create_pool", ngx_lua_dbd_create_pool },
    { "destroy_pool", ngx_lua_dbd_destroy_pool },
    { "execute", ngx_lua_dbd_execute },
    { NULL, NULL }
};


ngx_int_t
ngx_lua_dbd_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_lua_main_conf_t *olmcf = data;

    size_t                len;
    ngx_lua_main_conf_t  *lmcf;

    lmcf = shm_zone->data;

    if (olmcf) {
        lmcf->dbd = olmcf->dbd;
        lmcf->dbd_pool = olmcf->dbd_pool;
        return NGX_OK;
    }

    lmcf->dbd_pool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        lmcf->dbd = lmcf->dbd_pool->data;
        return NGX_OK;
    }

    lmcf->dbd = ngx_slab_alloc(lmcf->dbd_pool, sizeof(ngx_lua_dbd_t));
    if (lmcf->dbd == NULL) {
        return NGX_ERROR;
    }

    lmcf->dbd_pool->data = lmcf->dbd;

    ngx_rbtree_init(&lmcf->dbd->rbtree, &lmcf->dbd->sentinel,
                    ngx_lua_dbd_pool_insert_value);

    len = sizeof(" in lua dbd \"\"") + shm_zone->shm.name.len;

    lmcf->dbd_pool->log_ctx = ngx_slab_alloc(lmcf->dbd_pool, len);
    if (lmcf->dbd_pool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(lmcf->dbd_pool->log_ctx, " in lua dbd \"%V\"%Z",
                &shm_zone->shm.name);

    ngx_rbtree_init(&lmcf->dbd_rbtree, &lmcf->dbd_sentinel,
                    ngx_lua_dbd_insert_value);

    return NGX_OK;
}


void
ngx_lua_dbd_api_init(lua_State *l)
{
    int  n;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "lua dbd api init");

    n = sizeof(ngx_lua_dbd_methods) / sizeof(luaL_Reg) - 1;

    lua_createtable(l, 0, n);

    for (n = 0; ngx_lua_dbd_methods[n].name != NULL; n++) {
        lua_pushcfunction(l, ngx_lua_dbd_methods[n].func);
        lua_setfield(l, -2, ngx_lua_dbd_methods[n].name);
    }

    lua_setfield(l, -2, "database");
}


static int
ngx_lua_dbd_create_pool(lua_State *l)
{
    int                   n;
    char                 *errstr;
    size_t                size;
    u_char               *p;
    in_port_t             port;
    ngx_str_t             name, drv, host, db, user, passwd;
    ngx_uint_t            max_connections;
    ngx_http_request_t   *r;
    ngx_lua_dbd_conf_t   *conf;
    ngx_lua_main_conf_t  *lmcf;

    r = ngx_lua_request(l);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua dbd create pool");

    if (!lua_istable(l, 1)) {
        return luaL_error(l, "invalid argument, must be a table");
    }

    n = lua_gettop(l);

    lua_getfield(l, 1, "name");
    name.data = (u_char *) luaL_checklstring(l, -1, &name.len);

    lua_getfield(l, 1, "driver");
    drv.data = (u_char *) luaL_checklstring(l, -1, &drv.len);

    lua_getfield(l, 1, "host");
    host.data = (u_char *) luaL_checklstring(l, -1, &host.len);

    lua_getfield(l, 1, "port");
    port = (in_port_t) luaL_checknumber(l, -1);

    lua_getfield(l, 1, "database");
    db.data = (u_char *) luaL_checklstring(l, -1, &db.len);

    lua_getfield(l, 1, "user");
    user.data = (u_char *) luaL_checklstring(l, -1, &user.len);

    lua_getfield(l, 1, "password");
    passwd.data = (u_char *) luaL_checklstring(l, -1, &passwd.len);

    lua_getfield(l, 1, "max_connections");
    max_connections = (ngx_uint_t) luaL_checknumber(l, -1);

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_module);

    ngx_shmtx_lock(&lmcf->dbd_pool->mutex);

    conf = ngx_lua_dbd_pool_lookup(lmcf, &name);
    if (conf != NULL) {
        goto done;
    }

    /* TODO: alignment */

    size = sizeof(ngx_lua_dbd_conf_t)
           + name.len + drv.len + host.len
           + sizeof(in_port_t)
           + db.len + user.len + passwd.len
           + sizeof(ngx_uint_t);

    p = ngx_slab_alloc_locked(lmcf->dbd_pool, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "ngx_slab_alloc_locked() failed");
        errstr = "ngx_slab_alloc_locked() failed";
        goto error;
    }

    conf = (ngx_lua_dbd_conf_t *) p;
    p += sizeof(ngx_lua_dbd_conf_t);

    conf->name.len = name.len;
    conf->name.data = p;
    p = ngx_cpymem(conf->name.data, name.data, name.len);

    conf->drv.len = drv.len;
    conf->drv.data = p;
    p = ngx_cpymem(conf->drv.data, drv.data, drv.len);

    conf->host.len = host.len;
    conf->host.data = p;
    p = ngx_cpymem(conf->host.data, host.data, host.len);

    conf->port = port;

    conf->db.len = db.len;
    conf->db.data = p;
    p = ngx_cpymem(conf->db.data, db.data, db.len);

    conf->user.len = user.len;
    conf->user.data = p;
    p = ngx_cpymem(conf->user.data, user.data, user.len);

    conf->passwd.len = passwd.len;
    conf->passwd.data = p;
    p = ngx_cpymem(conf->passwd.data, passwd.data, passwd.len);

    conf->connection_n = max_connections;

    ngx_memzero(&conf->node, sizeof(ngx_rbtree_node_t));

    conf->node.key = ngx_crc32_short(name.data, name.len);
    ngx_rbtree_insert(&lmcf->dbd->rbtree, &conf->node);

done:

    ngx_shmtx_unlock(&lmcf->dbd_pool->mutex);

    lua_settop(l, n);
    lua_pushboolean(l, 1);

    return 1;

error:

    ngx_shmtx_unlock(&lmcf->dbd_pool->mutex);

    lua_settop(l, n);
    lua_pushboolean(l, 0);
    lua_pushstring(l, errstr);

    return 2;
}


static int
ngx_lua_dbd_destroy_pool(lua_State *l)
{
    ngx_str_t             name;
    ngx_http_request_t   *r;
    ngx_lua_dbd_conf_t   *conf;
    ngx_lua_main_conf_t  *lmcf;

    r = ngx_lua_request(l);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua dbd destroy pool");

    name.data = (u_char *) luaL_checklstring(l, -1, &name.len);

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_module);

    ngx_shmtx_lock(&lmcf->dbd_pool->mutex);

    conf = ngx_lua_dbd_pool_lookup(lmcf, &name);

    /* TODO */

    ngx_shmtx_unlock(&lmcf->dbd_pool->mutex);

    return 0;
}


static void
ngx_lua_dbd_pool_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t   **p;
    ngx_lua_dbd_conf_t   *conf, *conf_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            conf = (ngx_lua_dbd_conf_t *) node;
            conf_temp = (ngx_lua_dbd_conf_t *) temp;

            p = ngx_memn2cmp(conf->name.data, conf_temp->name.data,
                             conf->name.len, conf_temp->name.len)
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


static ngx_lua_dbd_conf_t *
ngx_lua_dbd_pool_lookup(ngx_lua_main_conf_t *lmcf, ngx_str_t *name)
{
    ngx_int_t            rc;
    ngx_rbtree_key_t     key;
    ngx_rbtree_node_t   *node, *sentinel;
    ngx_lua_dbd_conf_t  *conf;

    key = ngx_crc32_short(name->data, name->len);

    node = lmcf->dbd->rbtree.root;
    sentinel = lmcf->dbd->rbtree.sentinel;

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
            conf = (ngx_lua_dbd_conf_t *) node;

            rc = ngx_memn2cmp(conf->name.data, name->data, conf->name.len,
                              name->len);

            if (rc == 0) {
                return conf;
            }

            node = (rc < 0) ? node->left : node->right;

        } while (node != sentinel && key == node->key);

        break;
    }

    /* not found */

    return NULL;
}


static int
ngx_lua_dbd_execute(lua_State *l)
{
    char                       *errstr;
    ngx_str_t                   name, sql;
    ngx_int_t                   rc;
    ngx_pool_t                 *pool;
    ngx_lua_dbd_ctx_t          *ctx;
    ngx_http_cleanup_t         *cln;
    ngx_http_request_t         *r;
    ngx_lua_dbd_cleanup_ctx_t  *cln_ctx;

    r = ngx_lua_request(l);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua dbd execute");

    name.data = (u_char *) luaL_checklstring(l, 1, &name.len);
    sql.data = (u_char *) luaL_checklstring(l, 2, &sql.len);

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
        errstr = "ngx_create_pool() failed";
        goto error;
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_lua_dbd_ctx_t));
    if (ctx == NULL) {
        ngx_destroy_pool(pool);
        errstr = "ngx_pcalloc() failed";
        goto error;
    }

    ctx->pool = pool;
    ctx->lmcf = ngx_http_get_module_main_conf(r, ngx_lua_module);

    cln_ctx = ngx_pcalloc(r->pool, sizeof(ngx_lua_dbd_cleanup_ctx_t));
    if (cln_ctx == NULL) {
        ngx_destroy_pool(pool);
        errstr = "ngx_pcalloc() failed";
        goto error;
    }

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        ngx_destroy_pool(pool);
        errstr = "ngx_http_cleanup_add() failed";
        goto error;
    }

    cln->handler = ngx_lua_dbd_cleanup;
    cln->data = cln_ctx;

    ctx->r = r;
    ctx->cln_ctx = cln_ctx;

    ctx->c = ngx_lua_dbd_get_connection(r, &name);
    if (ctx->c == NULL) {
        ngx_destroy_pool(pool);
        errstr = "ngx_lua_dbd_get_connection() failed";
        goto error;
    }

    cln_ctx->ctx = ctx;

    /* TODO: escape sql */

    ngx_dbd_set_sql(ctx->c->dbd, sql.data, sql.len);

    lua_newtable(l);

    ctx->rc = 0;
    ctx->not_event = 1;

    if (!ctx->c->connected) {
        ngx_dbd_set_handler(ctx->c->dbd, ngx_lua_dbd_connect, ctx);

        ngx_lua_dbd_connect(ctx);

    } else {
        ngx_dbd_set_handler(ctx->c->dbd, ngx_lua_dbd_query, ctx);

        ngx_lua_dbd_query(ctx);
    }

    ctx->not_event = 0;

    rc = ctx->rc;

    if (rc == NGX_AGAIN) {
        return lua_yield(l, 0);
    }

    cln_ctx->ctx = NULL;

    ngx_destroy_pool(ctx->pool);

    return rc;

error:

    lua_pushboolean(l, 0);
    lua_pushstring(l, errstr);

    return 2;
}


static ngx_lua_dbd_connection_t *
ngx_lua_dbd_get_connection(ngx_http_request_t *r, ngx_str_t *name)
{
    size_t                     size;
    u_char                    *p, *drv, *host, *db, *user, *passwd;
    in_port_t                  port;
    ngx_uint_t                 max_connections;
    ngx_pool_t                *pool;
    ngx_queue_t               *q;
    ngx_lua_dbd_conf_t        *conf;
    ngx_lua_dbd_pool_t        *dbd_pool;
    ngx_lua_main_conf_t       *lmcf;
    ngx_lua_dbd_connection_t  *c;

    lmcf = ngx_http_get_module_main_conf(r, ngx_lua_module);

    ngx_shmtx_lock(&lmcf->dbd_pool->mutex);

    conf = ngx_lua_dbd_pool_lookup(lmcf, name);
    if (conf == NULL) {
        ngx_shmtx_unlock(&lmcf->dbd_pool->mutex);
        return NULL;
    }

    drv = ngx_palloc(r->pool, conf->drv.len + 1);
    if (drv == NULL) {
        ngx_shmtx_unlock(&lmcf->dbd_pool->mutex);
        return NULL;
    }
    ngx_cpystrn(drv, conf->drv.data, conf->drv.len + 1);

    host = ngx_palloc(r->pool, conf->host.len + 1);
    if (host == NULL) {
        ngx_shmtx_unlock(&lmcf->dbd_pool->mutex);
        return NULL;
    }
    ngx_cpystrn(host, conf->host.data, conf->host.len + 1);

    port = conf->port;

    db = ngx_palloc(r->pool, conf->db.len + 1);
    if (db == NULL) {
        ngx_shmtx_unlock(&lmcf->dbd_pool->mutex);
        return NULL;
    }
    ngx_cpystrn(db, conf->db.data, conf->db.len + 1);

    user = ngx_palloc(r->pool, conf->user.len + 1);
    if (user == NULL) {
        ngx_shmtx_unlock(&lmcf->dbd_pool->mutex);
        return NULL;
    }
    ngx_cpystrn(user, conf->user.data, conf->user.len + 1);

    passwd = ngx_palloc(r->pool, conf->passwd.len + 1);
    if (passwd == NULL) {
        ngx_shmtx_unlock(&lmcf->dbd_pool->mutex);
        return NULL;
    }
    ngx_cpystrn(passwd, conf->passwd.data, conf->passwd.len + 1);

    max_connections = conf->connection_n;

    ngx_shmtx_unlock(&lmcf->dbd_pool->mutex);

    dbd_pool = ngx_lua_dbd_lookup(lmcf, name);
    if (dbd_pool != NULL) {
        if (!ngx_queue_empty(&dbd_pool->free_connections)) {
            q = ngx_queue_last(&dbd_pool->free_connections);
            c = ngx_queue_data(q, ngx_lua_dbd_connection_t, queue);

            ngx_queue_remove(q);
            dbd_pool->free_connection_n--;

            ngx_queue_insert_head(&dbd_pool->connections, q);
            dbd_pool->connection_n++;

            return c;
        }

        if (dbd_pool->connection_n == max_connections) {
            return NULL;
        }

        goto new_connection;
    }

    size = sizeof(ngx_lua_dbd_pool_t) + name->len;

    p = ngx_calloc(size, ngx_cycle->log);
    if (p == NULL) {
        return NULL;
    }

    dbd_pool = (ngx_lua_dbd_pool_t *) p;
    p += sizeof(ngx_lua_dbd_pool_t);

    dbd_pool->name.len = name->len;
    dbd_pool->name.data = p;
    ngx_memcpy(dbd_pool->name.data, name->data, name->len);

    dbd_pool->node.key = ngx_crc32_short(name->data, name->len);
    ngx_rbtree_insert(&lmcf->dbd_rbtree, &dbd_pool->node);

    ngx_queue_init(&dbd_pool->connections);
    ngx_queue_init(&dbd_pool->free_connections);

new_connection:

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
        return NULL;
    }

    size = sizeof(ngx_lua_dbd_connection_t) + name->len;

    p = ngx_pcalloc(pool, size);
    if (p == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    c = (ngx_lua_dbd_connection_t *) p;
    p += sizeof(ngx_lua_dbd_connection_t);

    c->pool = pool;

    c->name.len = name->len;
    c->name.data = p;
    ngx_memcpy(c->name.data, name->data, name->len);

    c->dbd = ngx_dbd_create(pool, ngx_cycle->log, drv);
    if (c->dbd == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    ngx_dbd_set_options(c->dbd, NGX_DBD_OPT_NON_BLOCKING);
    ngx_dbd_set_tcp(c->dbd, host, port);
    ngx_dbd_set_auth(c->dbd, user, passwd);
    ngx_dbd_set_db(c->dbd, db);

    ngx_queue_insert_head(&dbd_pool->connections, &c->queue);
    dbd_pool->connection_n++;

    return c;
}


static void
ngx_lua_dbd_free_connection(ngx_lua_main_conf_t *lmcf,
    ngx_lua_dbd_connection_t *c)
{
    ngx_lua_dbd_pool_t  *pool;

    pool = ngx_lua_dbd_lookup(lmcf, &c->name);
    if (pool == NULL) {
        /* TODO: error handling */
        return;
    }

    ngx_queue_remove(&c->queue);
    pool->connection_n--;

    ngx_queue_insert_head(&pool->free_connections, &c->queue);
    pool->free_connection_n++;
}


static void
ngx_lua_dbd_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t   **p;
    ngx_lua_dbd_pool_t   *pool, *pool_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            pool = (ngx_lua_dbd_pool_t *) node;
            pool_temp = (ngx_lua_dbd_pool_t *) temp;

            p = ngx_memn2cmp(pool->name.data, pool_temp->name.data,
                             pool->name.len, pool_temp->name.len)
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


static ngx_lua_dbd_pool_t *
ngx_lua_dbd_lookup(ngx_lua_main_conf_t *lmcf, ngx_str_t *name)
{
    ngx_int_t            rc;
    ngx_rbtree_key_t     key;
    ngx_rbtree_node_t   *node, *sentinel;
    ngx_lua_dbd_pool_t  *pool;

    key = ngx_crc32_short(name->data, name->len);

    node = lmcf->dbd_rbtree.root;
    sentinel = lmcf->dbd_rbtree.sentinel;

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
            pool = (ngx_lua_dbd_pool_t *) node;

            rc = ngx_memn2cmp(pool->name.data, name->data, pool->name.len,
                              name->len);

            if (rc == 0) {
                return pool;
            }

            node = (rc < 0) ? node->left : node->right;

        } while (node != sentinel && key == node->key);

        break;
    }

    /* not found */

    return NULL;
}


static void
ngx_lua_dbd_connect(void *data)
{
    ngx_lua_dbd_ctx_t *ctx = data;

    ngx_int_t  rc;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "lua dbd connect");

    rc = ngx_dbd_connect(ctx->c->dbd);

    if (rc == NGX_AGAIN) {
        ctx->rc = NGX_AGAIN;
        return;
    }

    if (rc == NGX_ERROR) {
        ngx_lua_dbd_finalize(ctx, NGX_ERROR);
        return;
    }

    /* rc == NGX_OK */

    ctx->c->connected = 1;

    ngx_dbd_set_handler(ctx->c->dbd, ngx_lua_dbd_query, ctx);

    ngx_lua_dbd_query(ctx);
}


static void
ngx_lua_dbd_query(void *data)
{
    ngx_lua_dbd_ctx_t *ctx = data;

    ngx_int_t       rc;
    ngx_lua_ctx_t  *lua_ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "lua dbd query");

    rc = ngx_dbd_query(ctx->c->dbd);

    if (rc == NGX_AGAIN) {
        ctx->rc = NGX_AGAIN;
        return;
    }

    if (rc == NGX_ERROR) {
        ngx_lua_dbd_finalize(ctx, NGX_ERROR);
        return;
    }

    /* rc == NGX_OK */

    if (ctx->r != NULL) {
        lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

        lua_newtable(lua_ctx->l);
        lua_setfield(lua_ctx->l, -2, "columns");
    }

    ngx_dbd_set_handler(ctx->c->dbd, ngx_lua_dbd_column, ctx);

    ngx_lua_dbd_column(ctx);
}


static void
ngx_lua_dbd_column(void *data)
{
    ngx_lua_dbd_ctx_t *ctx = data;

    ngx_int_t       rc;
    ngx_lua_ctx_t  *lua_ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "lua dbd column");

    for ( ;; ) {

        rc = ngx_dbd_column_read(ctx->c->dbd);

        if (rc == NGX_AGAIN) {
            ctx->rc = NGX_AGAIN;
            return;
        }

        if (rc == NGX_ERROR) {
            ngx_lua_dbd_finalize(ctx, NGX_ERROR);
            return;
        }

        if (rc == NGX_DONE) {
            break;
        }

        /* rc == NGX_OK */

        if (ctx->r == NULL) {
            continue;
        }

        lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

        lua_getfield(lua_ctx->l, -1, "columns");
        lua_pushstring(lua_ctx->l, (char *) ngx_dbd_column_name(ctx->c->dbd));
        lua_rawseti(lua_ctx->l, -2, (int) ++ctx->col_count);
        lua_pop(lua_ctx->l, 1);
    }

    /* rc == NGX_DONE */

    if (ctx->r != NULL) {
        lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

        lua_newtable(lua_ctx->l);
        lua_setfield(lua_ctx->l, -2, "rows");
    }

    ngx_dbd_set_handler(ctx->c->dbd, ngx_lua_dbd_row, ctx);

    ngx_lua_dbd_row(ctx);
}


static void
ngx_lua_dbd_row(void *data)
{
    ngx_lua_dbd_ctx_t *ctx = data;

    ngx_int_t       rc;
    ngx_lua_ctx_t  *lua_ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "lua dbd row");

    for ( ;; ) {

        rc = ngx_dbd_row_read(ctx->c->dbd);

        if (rc == NGX_AGAIN) {
            ctx->rc = NGX_AGAIN;
            return;
        }

        if (rc == NGX_ERROR) {
            ngx_lua_dbd_finalize(ctx, NGX_ERROR);
            return;
        }

        if (rc == NGX_DONE) {
            break;
        }

        /* rc == NGX_OK */

        if (ctx->r != NULL) {
            lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

            lua_getfield(lua_ctx->l, -1, "rows");
            lua_newtable(lua_ctx->l);
            lua_rawseti(lua_ctx->l, -2, (int) ++ctx->row_count);
            lua_pop(lua_ctx->l, 1);
        }

        ctx->col_count = 0;

        ngx_dbd_set_handler(ctx->c->dbd, ngx_lua_dbd_field, ctx);

        ngx_lua_dbd_field(ctx);
        return;
    }

    /* rc == NGX_DONE */

    ngx_lua_dbd_finalize(ctx, NGX_OK);
}


static void
ngx_lua_dbd_field(void *data)
{
    ngx_lua_dbd_ctx_t *ctx = data;

    off_t           offset;
    size_t          size, total;
    u_char         *value;
    ngx_int_t       rc;
    ngx_lua_ctx_t  *lua_ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "lua dbd field");

    for ( ;; ) {

        rc = ngx_dbd_field_read(ctx->c->dbd, &value, &offset, &size, &total);

        if (rc == NGX_AGAIN) {
            ctx->rc = NGX_AGAIN;
            return;
        }

        if (rc == NGX_ERROR) {
            ngx_lua_dbd_finalize(ctx, NGX_ERROR);
            return;
        }

        if (rc == NGX_DONE) {
            break;
        }

        /* rc == NGX_OK */

        /* TODO: value, offset, size, total */

        if (ctx->r == NULL) {
            continue;
        }

        lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

        lua_getfield(lua_ctx->l, -1, "rows");
        lua_rawgeti(lua_ctx->l, -1, (int) ctx->row_count);
        lua_pushlstring(lua_ctx->l, (char *) value, size);
        lua_rawseti(lua_ctx->l, -2, (int) ++ctx->col_count);
        lua_pop(lua_ctx->l, 2);
    }

    ngx_dbd_set_handler(ctx->c->dbd, ngx_lua_dbd_row, ctx);

    ngx_lua_dbd_row(ctx);
}


static void
ngx_lua_dbd_finalize(ngx_lua_dbd_ctx_t *ctx, ngx_int_t rc)
{
    ngx_lua_ctx_t       *lua_ctx;
    ngx_http_request_t  *r;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "lua dbd finalize");

    if (ctx->cln_ctx != NULL) {
        ctx->cln_ctx->ctx = NULL;
    }

    r = ctx->r;

    if (r == NULL) {
        ngx_lua_dbd_free_connection(ctx->lmcf, ctx->c);
        ngx_destroy_pool(ctx->pool);
        return;
    }

    lua_ctx = ngx_http_get_module_ctx(r, ngx_lua_module);

    ctx->rc = 1;

    if (rc == NGX_OK) {
        lua_pushnumber(lua_ctx->l,
                       (lua_Number) ngx_dbd_result_column_count(ctx->c->dbd));
        lua_setfield(lua_ctx->l, -2, "col_count");

        lua_pushnumber(lua_ctx->l, (lua_Number) ctx->row_count);
        lua_setfield(lua_ctx->l, -2, "row_count");

        lua_pushnumber(lua_ctx->l,
                       (lua_Number) ngx_dbd_result_affected_rows(ctx->c->dbd));
        lua_setfield(lua_ctx->l, -2, "affected_rows");

        lua_pushnumber(lua_ctx->l,
                       (lua_Number) ngx_dbd_result_insert_id(ctx->c->dbd));
        lua_setfield(lua_ctx->l, -2, "insert_id");

    } else {

        lua_pop(lua_ctx->l, 1);
        lua_pushboolean(lua_ctx->l, 0);
        lua_pushstring(lua_ctx->l, (char *) ngx_dbd_error(ctx->c->dbd));

        ctx->rc++;
    }

    ngx_lua_dbd_free_connection(ctx->lmcf, ctx->c);

    if (ctx->not_event) {
        return;
    }

    rc = ctx->rc;

    ngx_destroy_pool(ctx->pool);

    rc = ngx_lua_thread_run(r, lua_ctx, rc);
    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_lua_finalize(r, rc);
}


static void
ngx_lua_dbd_cleanup(void *data)
{
    ngx_lua_dbd_cleanup_ctx_t *cln_ctx = data;

    if (cln_ctx->ctx != NULL) {
        cln_ctx->ctx->r = NULL;
        cln_ctx->ctx->cln_ctx = NULL;
    }
}
