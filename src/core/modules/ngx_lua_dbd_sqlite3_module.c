
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_dbd.h>
#include <ngx_lua.h>


static ngx_int_t ngx_lua_dbd_sqlite3_module_init(ngx_cycle_t *cycle);


ngx_module_t  ngx_lua_dbd_sqlite3_module = {
    NGX_MODULE_V1,
    NULL,                                  /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_lua_dbd_sqlite3_module_init,       /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


extern ngx_dbd_driver_t  ngx_dbd_sqlite3_driver;


#if (NGX_LUA_DLL)
ngx_module_t **
ngx_lua_get_modules(void)
{
    static ngx_module_t  *modules[] = {
        &ngx_lua_dbd_sqlite3_module,
        NULL
    };

    return modules;
}
#endif


static ngx_int_t
ngx_lua_dbd_sqlite3_module_init(ngx_cycle_t *cycle)
{
    if (ngx_dbd_add_driver(&ngx_dbd_sqlite3_driver) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
