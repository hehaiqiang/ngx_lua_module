
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_dbd.h>
#include <ngx_lua_module.h>


typedef struct {
    ngx_http_request_t    *r;
    ngx_dbd_t             *dbd;
    ngx_uint_t             connected;
    uint64_t               row_count;
    uint64_t               col_count;
} ngx_lua_dbd_ctx_t;


static int ngx_lua_dbd_execute(lua_State *l);

static void ngx_lua_dbd_connect(void *data);
static void ngx_lua_dbd_query(void *data);
static void ngx_lua_dbd_column(void *data);
static void ngx_lua_dbd_row(void *data);
static void ngx_lua_dbd_field(void *data);

static void ngx_lua_dbd_error(ngx_lua_dbd_ctx_t *ctx);
static void ngx_lua_dbd_cleanup(void *data);


void
ngx_lua_dbd_api_init(lua_State *l)
{
    lua_createtable(l, 0, 1);
    lua_pushcfunction(l, ngx_lua_dbd_execute);
    lua_setfield(l, -2, "execute");
    lua_setfield(l, -2, "database");
}


static int
ngx_lua_dbd_execute(lua_State *l)
{
    u_char              *drv, *host, *user, *passwd, *db;
    in_port_t            port;
    ngx_str_t            sql;
    ngx_lua_dbd_ctx_t   *ctx;
    ngx_http_cleanup_t  *cln;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    if (!lua_istable(l, -1)) {
        return luaL_error(l, "invalid argument, must be a table");
    }

    lua_getfield(l, -1, "driver");
    drv = (u_char *) luaL_checkstring(l, -1);

    lua_getfield(l, -2, "host");
    host = (u_char *) luaL_checkstring(l, -1);

    lua_getfield(l, -3, "port");
    port = (in_port_t) luaL_checkint(l, -1);

    lua_getfield(l, -4, "user");
    user = (u_char *) luaL_checkstring(l, -1);

    lua_getfield(l, -5, "password");
    passwd = (u_char *) luaL_checkstring(l, -1);

    lua_getfield(l, -6, "database");
    db = (u_char *) luaL_checkstring(l, -1);

    lua_getfield(l, -7, "sql");
    sql.data = (u_char *) luaL_checklstring(l, -1, &sql.len);

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_lua_dbd_ctx_t));
    if (ctx == NULL) {
        lua_pop(l, 7);
        return luaL_error(l, "ngx_pcalloc() failed");
    }

    ctx->r = r;

    ctx->dbd = ngx_dbd_create(r->pool, r->connection->log, drv);
    if (ctx->dbd == NULL) {
        lua_pop(l, 7);
        return luaL_error(l, "ngx_dbd_create() failed");
    }

    ngx_dbd_set_options(ctx->dbd, NGX_DBD_OPT_NON_BLOCKING);
    ngx_dbd_set_tcp(ctx->dbd, host, port);
    ngx_dbd_set_auth(ctx->dbd, user, passwd);
    ngx_dbd_set_db(ctx->dbd, db);

    /* TODO: escape sql */

    ngx_dbd_set_sql(ctx->dbd, sql.data, sql.len);

    lua_pop(l, 7);

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        ngx_dbd_destroy(ctx->dbd);
        return luaL_error(l, "ngx_http_cleanup_add() failed");
    }

    cln->handler = ngx_lua_dbd_cleanup;
    cln->data = ctx;

    /* creating a new lua table to store results */

    lua_newtable(l);

    ngx_dbd_set_handler(ctx->dbd, ngx_lua_dbd_connect, ctx);

    ngx_lua_dbd_connect(ctx);

    return lua_yield(l, 0);
}


static void
ngx_lua_dbd_connect(void *data)
{
    ngx_lua_dbd_ctx_t *ctx = data;

    ngx_int_t  rc;

    rc = ngx_dbd_connect(ctx->dbd);

    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc == NGX_ERROR) {
        ngx_lua_dbd_error(ctx);
        return;
    }

    /* rc == NGX_OK */

    ctx->connected = 1;

    ngx_dbd_set_handler(ctx->dbd, ngx_lua_dbd_query, ctx);

    ngx_lua_dbd_query(ctx);
}


static void
ngx_lua_dbd_query(void *data)
{
    ngx_lua_dbd_ctx_t *ctx = data;

    ngx_int_t       rc;
    ngx_lua_ctx_t  *lua_ctx;

    rc = ngx_dbd_query(ctx->dbd);

    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc == NGX_ERROR) {
        ngx_lua_dbd_error(ctx);
        return;
    }

    /* rc == NGX_OK */

    lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

    lua_newtable(lua_ctx->l);
    lua_setfield(lua_ctx->l, -2, "columns");

    ngx_dbd_set_handler(ctx->dbd, ngx_lua_dbd_column, ctx);

    ngx_lua_dbd_column(ctx);
}


static void
ngx_lua_dbd_column(void *data)
{
    ngx_lua_dbd_ctx_t *ctx = data;

    ngx_int_t       rc;
    ngx_lua_ctx_t  *lua_ctx;

    lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

    for ( ;; ) {

        rc = ngx_dbd_column_read(ctx->dbd);

        if (rc == NGX_AGAIN) {
            return;
        }

        if (rc == NGX_ERROR) {
            ngx_lua_dbd_error(ctx);
            return;
        }

        if (rc == NGX_DONE) {
            break;
        }

        /* rc == NGX_OK */

        ctx->col_count++;

        lua_getfield(lua_ctx->l, -1, "columns");
        lua_pushstring(lua_ctx->l, (char *) ngx_dbd_column_name(ctx->dbd));
        lua_rawseti(lua_ctx->l, -2, (int) ctx->col_count);
        lua_pop(lua_ctx->l, 1);
    }

    /* rc == NGX_DONE */

    lua_newtable(lua_ctx->l);
    lua_setfield(lua_ctx->l, -2, "rows");

    ngx_dbd_set_handler(ctx->dbd, ngx_lua_dbd_row, ctx);

    ngx_lua_dbd_row(ctx);
}


static void
ngx_lua_dbd_row(void *data)
{
    ngx_lua_dbd_ctx_t *ctx = data;

    ngx_int_t       rc;
    lua_State      *l;
    ngx_lua_ctx_t  *lua_ctx;

    lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

    for ( ;; ) {

        rc = ngx_dbd_row_read(ctx->dbd);

        if (rc == NGX_AGAIN) {
            return;
        }

        if (rc == NGX_ERROR) {
            ngx_lua_dbd_error(ctx);
            return;
        }

        if (rc == NGX_DONE) {
            break;
        }

        /* rc == NGX_OK */

        ctx->row_count++;
        ctx->col_count = 0;

        lua_getfield(lua_ctx->l, -1, "rows");
        lua_newtable(lua_ctx->l);
        lua_rawseti(lua_ctx->l, -2, (int) ctx->row_count);
        lua_pop(lua_ctx->l, 1);

        ngx_dbd_set_handler(ctx->dbd, ngx_lua_dbd_field, ctx);

        ngx_lua_dbd_field(ctx);

        return;
    }

    /* rc == NGX_DONE */

    l = lua_ctx->l;

    lua_pushnumber(l, 0);
    lua_setfield(l, -2, "err");

    lua_pushstring(l, "");
    lua_setfield(l, -2, "errstr");

    lua_pushnumber(l, (lua_Number) ngx_dbd_result_column_count(ctx->dbd));
    lua_setfield(l, -2, "col_count");

    lua_pushnumber(l, (lua_Number) ctx->row_count);
    lua_setfield(l, -2, "row_count");

    lua_pushnumber(l, (lua_Number) ngx_dbd_result_affected_rows(ctx->dbd));
    lua_setfield(l, -2, "affected_rows");

    lua_pushnumber(l, (lua_Number) ngx_dbd_result_insert_id(ctx->dbd));
    lua_setfield(l, -2, "insert_id");

    ngx_lua_dbd_cleanup(ctx);

    rc = ngx_lua_thread_run(ctx->r, lua_ctx, 1);
    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_lua_finalize(ctx->r, rc);
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

    for ( ;; ) {

        rc = ngx_dbd_field_read(ctx->dbd, &value, &offset, &size, &total);

        if (rc == NGX_AGAIN) {
            return;
        }

        if (rc == NGX_ERROR) {
            ngx_lua_dbd_error(ctx);
            return;
        }

        if (rc == NGX_DONE) {
            break;
        }

        /* rc == NGX_OK */

        ctx->col_count++;

        /* TODO: value, offset, size, total */

        lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

        lua_getfield(lua_ctx->l, -1, "rows");
        lua_rawgeti(lua_ctx->l, -1, (int) ctx->row_count);
        lua_pushlstring(lua_ctx->l, (char *) value, size);
        lua_rawseti(lua_ctx->l, -2, (int) ctx->col_count);
        lua_pop(lua_ctx->l, 2);
    }

    ngx_dbd_set_handler(ctx->dbd, ngx_lua_dbd_row, ctx);

    ngx_lua_dbd_row(ctx);
}


static void
ngx_lua_dbd_error(ngx_lua_dbd_ctx_t *ctx)
{
    u_char         *errstr;
    ngx_err_t       err;
    ngx_int_t       rc;
    ngx_lua_ctx_t  *lua_ctx;

    lua_ctx = ngx_http_get_module_ctx(ctx->r, ngx_lua_module);

    err = ngx_dbd_error_code(ctx->dbd);
    errstr = ngx_dbd_error(ctx->dbd);

    if (err == 0) {
        err = (ngx_err_t) NGX_ERROR;
    }

    lua_pushnumber(lua_ctx->l, err);
    lua_setfield(lua_ctx->l, -2, "err");

    lua_pushstring(lua_ctx->l, (char *) errstr);
    lua_setfield(lua_ctx->l, -2, "errstr");

    ngx_lua_dbd_cleanup(ctx);

    rc = ngx_lua_thread_run(ctx->r, lua_ctx, 1);
    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_lua_finalize(ctx->r, rc);
}


static void
ngx_lua_dbd_cleanup(void *data)
{
    ngx_lua_dbd_ctx_t *ctx = data;

    if (ctx->dbd) {
        if (ctx->connected) {
            ngx_dbd_close(ctx->dbd);
        }

        ngx_dbd_destroy(ctx->dbd);

        ctx->dbd = NULL;
    }
}
