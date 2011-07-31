
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_api.h>


#define NGX_LUA_DBD  "ngx_dbd_t*"


#define NGX_LUA_DBD_CMD_CONNECT     1
#define NGX_LUA_DBD_CMD_QUERY       2
#define NGX_LUA_DBD_CMD_READ_COL    3
#define NGX_LUA_DBD_CMD_READ_ROW    4
#define NGX_LUA_DBD_CMD_READ_FIELD  5


static int ngx_lua_dbd_create(lua_State *l);
static int ngx_lua_dbd_destroy(lua_State *l);
static int ngx_lua_dbd_set_options(lua_State *l);
static int ngx_lua_dbd_get_options(lua_State *l);
static int ngx_lua_dbd_escape(lua_State *l);
static int ngx_lua_dbd_error(lua_State *l);
static int ngx_lua_dbd_error_code(lua_State *l);
static int ngx_lua_dbd_connect(lua_State *l);
static int ngx_lua_dbd_close(lua_State *l);
static int ngx_lua_dbd_query(lua_State *l);
static int ngx_lua_dbd_result_buffer(lua_State *l);
static int ngx_lua_dbd_result_warning_count(lua_State *l);
static int ngx_lua_dbd_result_insert_id(lua_State *l);
static int ngx_lua_dbd_result_affected_rows(lua_State *l);
static int ngx_lua_dbd_result_column_count(lua_State *l);
static int ngx_lua_dbd_result_row_count(lua_State *l);
static int ngx_lua_dbd_column_skip(lua_State *l);
static int ngx_lua_dbd_column_buffer(lua_State *l);
static int ngx_lua_dbd_column_read(lua_State *l);
static int ngx_lua_dbd_column_catalog(lua_State *l);
static int ngx_lua_dbd_column_db(lua_State *l);
static int ngx_lua_dbd_column_table(lua_State *l);
static int ngx_lua_dbd_column_orig_table(lua_State *l);
static int ngx_lua_dbd_column_name(lua_State *l);
static int ngx_lua_dbd_column_orig_name(lua_State *l);
static int ngx_lua_dbd_column_charset(lua_State *l);
static int ngx_lua_dbd_column_size(lua_State *l);
static int ngx_lua_dbd_column_max_size(lua_State *l);
static int ngx_lua_dbd_column_type(lua_State *l);
static int ngx_lua_dbd_column_flags(lua_State *l);
static int ngx_lua_dbd_column_decimals(lua_State *l);
static int ngx_lua_dbd_column_default_value(lua_State *l);
static int ngx_lua_dbd_row_buffer(lua_State *l);
static int ngx_lua_dbd_row_read(lua_State *l);
static int ngx_lua_dbd_field_buffer(lua_State *l);
static int ngx_lua_dbd_field_read(lua_State *l);

static int ngx_lua_dbd_gc(lua_State *l);
static int ngx_lua_dbd_tostring(lua_State *l);

static ngx_inline ngx_dbd_t *ngx_lua_dbd(lua_State *l);
static int ngx_lua_dbd_handle_command(lua_State *l, ngx_dbd_t *dbd, int cmd);
static void ngx_lua_dbd_handler(void *data);


static luaL_Reg  ngx_lua_dbd_methods[] = {
    { "destroy", ngx_lua_dbd_destroy },
    { "set_options", ngx_lua_dbd_set_options },
    { "get_options", ngx_lua_dbd_get_options },
    { "escape", ngx_lua_dbd_escape },
    { "error", ngx_lua_dbd_error },
    { "error_code", ngx_lua_dbd_error_code },
    { "connect", ngx_lua_dbd_connect },
    { "close", ngx_lua_dbd_close },
    { "query", ngx_lua_dbd_query },
    { "result_buffer", ngx_lua_dbd_result_buffer },
    { "result_warning_count", ngx_lua_dbd_result_warning_count },
    { "result_insert_id", ngx_lua_dbd_result_insert_id },
    { "result_affected_rows", ngx_lua_dbd_result_affected_rows },
    { "result_column_count", ngx_lua_dbd_result_column_count },
    { "result_row_count", ngx_lua_dbd_result_row_count },
    { "column_skip", ngx_lua_dbd_column_skip },
    { "column_buffer", ngx_lua_dbd_column_buffer },
    { "column_read", ngx_lua_dbd_column_read },
    { "column_catalog", ngx_lua_dbd_column_catalog },
    { "column_db", ngx_lua_dbd_column_db },
    { "column_table", ngx_lua_dbd_column_table },
    { "column_orig_table", ngx_lua_dbd_column_orig_table },
    { "column_name", ngx_lua_dbd_column_name },
    { "column_orig_name", ngx_lua_dbd_column_orig_name },
    { "column_charset", ngx_lua_dbd_column_charset },
    { "column_size", ngx_lua_dbd_column_size },
    { "column_max_size", ngx_lua_dbd_column_max_size },
    { "column_type", ngx_lua_dbd_column_type },
    { "column_flags", ngx_lua_dbd_column_flags },
    { "column_decimals", ngx_lua_dbd_column_decimals },
    { "column_default_value", ngx_lua_dbd_column_default_value },
    { "row_buffer", ngx_lua_dbd_row_buffer },
    { "row_read", ngx_lua_dbd_row_read },
    { "field_buffer", ngx_lua_dbd_field_buffer },
    { "field_read", ngx_lua_dbd_field_read },
    { "__gc", ngx_lua_dbd_gc },
    { "__tostring", ngx_lua_dbd_tostring },
    { NULL, NULL }
};


void
ngx_lua_dbd_api_init(lua_State *l)
{
    int  i;

    luaL_newmetatable(l, NGX_LUA_DBD);
    lua_pushvalue(l, -1);
    lua_setfield(l, -2, "__index");

    for (i = 0; ngx_lua_dbd_methods[i].name != NULL; i++) {
        lua_pushcfunction(l, ngx_lua_dbd_methods[i].func);
        lua_setfield(l, -2, ngx_lua_dbd_methods[i].name);
    }

    lua_pop(l, 1);

    lua_createtable(l, 0, 1);
    lua_pushcfunction(l, ngx_lua_dbd_create);
    lua_setfield(l, -2, "create");
    lua_setfield(l, -2, "dbd");
}


static int
ngx_lua_dbd_create(lua_State *l)
{
    u_char               *drv;
    ngx_dbd_t           **dbd;
    ngx_http_request_t   *r;

    r = ngx_lua_request(l);

    drv = (u_char *) luaL_checkstring(l, 1);

    dbd = lua_newuserdata(l, sizeof(ngx_dbd_t *));
    luaL_getmetatable(l, NGX_LUA_DBD);
    lua_setmetatable(l, -2);

    *dbd = ngx_dbd_create(r->pool, r->connection->log, drv);
    if (*dbd == NULL) {
        return 0;
    }

    ngx_dbd_set_options(*dbd, NGX_DBD_OPT_NON_BLOCKING);
    ngx_dbd_set_handler(*dbd, ngx_lua_dbd_handler, r);

    return 1;
}


static int
ngx_lua_dbd_destroy(lua_State *l)
{
    ngx_dbd_t  *dbd;

    dbd = ngx_lua_dbd(l);
    ngx_dbd_destroy(dbd);

    return 0;
}


static int
ngx_lua_dbd_set_options(lua_State *l)
{
    int         opts;
    ngx_dbd_t  *dbd;

    dbd = ngx_lua_dbd(l);
    opts = luaL_checkint(l, 2);

    ngx_dbd_set_options(dbd, opts);

    return 0;
}


static int
ngx_lua_dbd_get_options(lua_State *l)
{
    int         opts;
    ngx_dbd_t  *dbd;

    dbd = ngx_lua_dbd(l);
    opts = ngx_dbd_get_options(dbd);

    lua_pushnumber(l, opts);

    return 1;
}


static int
ngx_lua_dbd_escape(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_error(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_error_code(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_connect(lua_State *l)
{
    int         n, port;
    u_char     *uds, *host, *user, *passwd, *db;
    ngx_dbd_t  *dbd;

    dbd = ngx_lua_dbd(l);

    n = lua_gettop(l) - 1;

    if (n == 5) {
        host = (u_char *) luaL_checkstring(l, 2);
        port = luaL_checkint(l, 3);
        n = 4;
        ngx_dbd_set_tcp(dbd, host, (in_port_t) port);

    } else if (n == 4) {
        uds = (u_char *) luaL_checkstring(l, 2);
        n = 3;
        ngx_dbd_set_uds(dbd, uds);

    } else {
        /* TODO: error handling */
        return 0;
    }

    user = (u_char *) luaL_checkstring(l, n++);
    passwd = (u_char *) luaL_checkstring(l, n++);
    db = (u_char *) luaL_checkstring(l, n);

    ngx_dbd_set_auth(dbd, user, passwd);
    ngx_dbd_set_db(dbd, db);

    n = ngx_lua_dbd_handle_command(l, dbd, NGX_LUA_DBD_CMD_CONNECT);
    if (n != NGX_AGAIN) {
        return n;
    }

    return lua_yield(l, 0);
}


static int
ngx_lua_dbd_close(lua_State *l)
{
    ngx_dbd_t  *dbd;

    dbd = ngx_lua_dbd(l);
    ngx_dbd_close(dbd);

    return 0;
}


static int
ngx_lua_dbd_query(lua_State *l)
{
    int         n;
    ngx_str_t   sql;
    ngx_dbd_t  *dbd;

    dbd = ngx_lua_dbd(l);

    sql.data = (u_char *) luaL_checklstring(l, 2, &sql.len);
    ngx_dbd_set_sql(dbd, sql.data, sql.len);

    n = ngx_lua_dbd_handle_command(l, dbd, NGX_LUA_DBD_CMD_QUERY);
    if (n != NGX_AGAIN) {
        return n;
    }

    return lua_yield(l, 0);
}


static int
ngx_lua_dbd_result_buffer(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_result_warning_count(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_result_insert_id(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_result_affected_rows(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_result_column_count(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_result_row_count(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_column_skip(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_column_buffer(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_column_read(lua_State *l)
{
    int         n;
    ngx_dbd_t  *dbd;

    dbd = ngx_lua_dbd(l);

    n = ngx_lua_dbd_handle_command(l, dbd, NGX_LUA_DBD_CMD_READ_COL);
    if (n != NGX_AGAIN) {
        return n;
    }

    return lua_yield(l, 0);
}


static int
ngx_lua_dbd_column_catalog(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_column_db(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_column_table(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_column_orig_table(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_column_name(lua_State *l)
{
    u_char     *name;
    ngx_dbd_t  *dbd;

    dbd = ngx_lua_dbd(l);
    name = ngx_dbd_column_name(dbd);

    lua_pushstring(l, (char *) name);

    return 1;
}


static int
ngx_lua_dbd_column_orig_name(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_column_charset(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_column_size(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_column_max_size(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_column_type(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_column_flags(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_column_decimals(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_column_default_value(lua_State *l)
{
    /* TODO */

    return 2;
}


static int
ngx_lua_dbd_row_buffer(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_row_read(lua_State *l)
{
    int         n;
    ngx_dbd_t  *dbd;

    dbd = ngx_lua_dbd(l);

    n = ngx_lua_dbd_handle_command(l, dbd, NGX_LUA_DBD_CMD_READ_ROW);
    if (n != NGX_AGAIN) {
        return n;
    }

    return lua_yield(l, 0);
}


static int
ngx_lua_dbd_field_buffer(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_field_read(lua_State *l)
{
    int         n;
    ngx_dbd_t  *dbd;

    dbd = ngx_lua_dbd(l);

    n = ngx_lua_dbd_handle_command(l, dbd, NGX_LUA_DBD_CMD_READ_FIELD);
    if (n != NGX_AGAIN) {
        return n;
    }

    return lua_yield(l, 0);
}


static int
ngx_lua_dbd_gc(lua_State *l)
{
    /* TODO */

    return 0;
}


static int
ngx_lua_dbd_tostring(lua_State *l)
{
    /* TODO */

    return 0;
}


static ngx_inline ngx_dbd_t *
ngx_lua_dbd(lua_State *l)
{
    ngx_dbd_t  **dbd;

    dbd = luaL_checkudata(l, 1, NGX_LUA_DBD);
    if (*dbd == NULL) {
        luaL_error(l, "attempt to use a destroyed dbd");
    }

    return *dbd;
}


static int
ngx_lua_dbd_handle_command(lua_State *l, ngx_dbd_t *dbd, int cmd)
{
    off_t                offset;
    size_t               size, total;
    u_char              *value;
    ngx_int_t            rc;
    ngx_lua_ctx_t       *ctx;
    ngx_http_request_t  *r;

    r = ngx_lua_request(l);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua dbd handle command");

    ctx = ngx_http_get_module_ctx(r, ngx_lua_module);

    ctx->dbd = dbd;
    ctx->cmd = cmd;

    switch (cmd) {
    case NGX_LUA_DBD_CMD_CONNECT:
        rc = ngx_dbd_connect(dbd);
        break;
    case NGX_LUA_DBD_CMD_QUERY:
        rc = ngx_dbd_query(dbd);
        break;
    case NGX_LUA_DBD_CMD_READ_COL:
        rc = ngx_dbd_column_read(dbd);
        break;
    case NGX_LUA_DBD_CMD_READ_ROW:
        rc = ngx_dbd_row_read(dbd);
        break;
    case NGX_LUA_DBD_CMD_READ_FIELD:
        rc = ngx_dbd_field_read(dbd, &value, &offset, &size, &total);
        if (rc != NGX_OK) {
            break;
        }

        lua_pushlstring(l, (char *) value, size);
        return 1;
    default:
        return 0;
    }

    if (rc == NGX_AGAIN) {
        return rc;
    }

    lua_pushnumber(l, rc);

    return 1;
}


static void
ngx_lua_dbd_handler(void *data)
{
    ngx_http_request_t *r = data;

    int             n;
    ngx_int_t       rc;
    ngx_lua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua dbd handler");

    ctx = ngx_http_get_module_ctx(r, ngx_lua_module);

    n = ngx_lua_dbd_handle_command(ctx->l, ctx->dbd, ctx->cmd);
    if (n == NGX_AGAIN) {
        return;
    }

    rc = ngx_lua_thread_run(r, ctx, n);
    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_lua_finalize(r, rc);
}
