
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_module.h>


static ngx_int_t ngx_lua_process_init(ngx_cycle_t *cycle);

static ngx_int_t ngx_lua_init(ngx_conf_t *cf);
static void *ngx_lua_create_main_conf(ngx_conf_t *cf);
static char *ngx_lua_init_main_conf(ngx_conf_t *cf, void *conf);
static char *ngx_lua_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_lua_dbd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_lua(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_lua_commands[] = {

    { ngx_string("lua_package_path"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_lua_main_conf_t, path),
      NULL },

    { ngx_string("lua_package_cpath"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_lua_main_conf_t, cpath),
      NULL },

    { ngx_string("lua_cache"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
      ngx_lua_cache,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("lua_dbd"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_lua_dbd,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("lua"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_NOARGS,
      ngx_lua,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_lua_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_lua_init,                          /* postconfiguration */

    ngx_lua_create_main_conf,              /* create main configuration */
    ngx_lua_init_main_conf,                /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_lua_module = {
    NGX_MODULE_V1,
    &ngx_lua_module_ctx,                   /* module context */
    ngx_lua_commands,                      /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_lua_process_init,                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_lua_process_init(ngx_cycle_t *cycle)
{
    ngx_lua_main_conf_t  *lmcf;

    lmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_lua_module);

    lmcf->cache_event.handler = ngx_lua_cache_expire;
    lmcf->cache_event.data = lmcf;
    lmcf->cache_event.log = cycle->log;

    ngx_add_timer(&lmcf->cache_event, lmcf->cache_expire * 1000 / 10);

    return NGX_OK;
}


static ngx_int_t
ngx_lua_init(ngx_conf_t *cf)
{
    /* TODO: set header and body filter */

    return NGX_OK;
}


static void *
ngx_lua_create_main_conf(ngx_conf_t *cf)
{
    ngx_lua_main_conf_t  *lmcf;

    lmcf = ngx_pcalloc(cf->pool, sizeof(ngx_lua_main_conf_t));
    if (lmcf == NULL) {
        return NULL;
    }

    lmcf->cache_size = NGX_CONF_UNSET_SIZE;
    lmcf->cache_expire = NGX_CONF_UNSET;

    lmcf->dbd_size = NGX_CONF_UNSET_SIZE;

    return lmcf;
}


static char *
ngx_lua_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_lua_main_conf_t *lmcf = conf;

    ngx_pool_cleanup_t  *cln;

    /* cache */

    if (lmcf->cache_name.data == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                          "the directive \"lua_cache\" must be specified");
        return NGX_CONF_ERROR;
    }

    ngx_conf_init_size_value(lmcf->cache_size, 1024 * 1024 * 1);
    ngx_conf_init_value(lmcf->cache_expire, 30 * 60);

    lmcf->cache_zone = ngx_shared_memory_add(cf, &lmcf->cache_name,
                                             lmcf->cache_size, &ngx_lua_module);
    if (lmcf->cache_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (lmcf->cache_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate lua cache name \"%V\"",
                           &lmcf->cache_name);
        return NGX_CONF_ERROR;
    }

    lmcf->cache_zone->init = ngx_lua_cache_init;
    lmcf->cache_zone->data = lmcf;

    /* dbd */

    if (lmcf->dbd_name.data == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                          "the directive \"lua_dbd\" must be specified");
        return NGX_CONF_ERROR;
    }

    ngx_conf_init_size_value(lmcf->dbd_size, 1024 * 512);

    lmcf->dbd_zone = ngx_shared_memory_add(cf, &lmcf->dbd_name, lmcf->dbd_size,
                                           &ngx_lua_module);
    if (lmcf->dbd_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (lmcf->dbd_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate lua dbd name \"%V\"", &lmcf->dbd_name);
        return NGX_CONF_ERROR;
    }

    lmcf->dbd_zone->init = ngx_lua_dbd_init;
    lmcf->dbd_zone->data = lmcf;

    if (ngx_lua_create(cf, lmcf) == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        ngx_lua_destroy(lmcf->l);
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_lua_destroy;
    cln->data = lmcf->l;

    return NGX_CONF_OK;
}


static char *
ngx_lua_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_lua_main_conf_t *lmcf = conf;

    ngx_str_t   *value, str;
    ngx_uint_t   i;

    if (lmcf->cache_name.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "name=", 5) == 0) {
            lmcf->cache_name.len = value[i].len - 5;
            lmcf->cache_name.data = value[i].data + 5;
            continue;
        }

        if (ngx_strncmp(value[i].data, "size=", 5) == 0) {
            str.len = value[i].len - 5;
            str.data = value[i].data + 5;
            lmcf->cache_size = ngx_parse_size(&str);
            if (lmcf->cache_size == (size_t) NGX_ERROR) {
                goto invalid;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "expire=", 7) == 0) {
            str.len = value[i].len - 7;
            str.data = value[i].data + 7;
            lmcf->cache_expire = ngx_parse_time(&str, 1);
            if (lmcf->cache_expire == NGX_ERROR) {
                goto invalid;
            }
            continue;
        }

        goto invalid;
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\" in lua_cache", &value[i]);

    return NGX_CONF_ERROR;
}


static char *
ngx_lua_dbd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_lua_main_conf_t *lmcf = conf;

    ngx_str_t   *value, str;
    ngx_uint_t   i;

    if (lmcf->dbd_name.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "name=", 5) == 0) {
            lmcf->dbd_name.len = value[i].len - 5;
            lmcf->dbd_name.data = value[i].data + 5;
            continue;
        }

        if (ngx_strncmp(value[i].data, "size=", 5) == 0) {
            str.len = value[i].len - 5;
            str.data = value[i].data + 5;
            lmcf->dbd_size = ngx_parse_size(&str);
            if (lmcf->dbd_size == (size_t) NGX_ERROR) {
                goto invalid;
            }
            continue;
        }

        goto invalid;
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\" in lua_dbd", &value[i]);

    return NGX_CONF_ERROR;
}


static char *
ngx_lua(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_lua_handler;

    return NGX_CONF_OK;
}
