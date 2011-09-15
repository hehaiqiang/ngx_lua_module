
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_session.h>


static ngx_int_t ngx_session_init_session(ngx_udp_session_t *s);
static void ngx_session_process_session(ngx_udp_session_t *s);

static void *ngx_session_create_main_conf(ngx_conf_t *cf);
static char *ngx_session_init_main_conf(ngx_conf_t *cf, void *conf);


static ngx_udp_protocol_t  ngx_session_protocol = {
    ngx_string("session"),
    ngx_session_init_session,
    NULL,
    ngx_session_process_session,
    NULL,
    NULL
};


static ngx_command_t  ngx_session_commands[] = {

      ngx_null_command
};


static ngx_udp_module_t  ngx_session_module_ctx = {
    &ngx_session_protocol,                 /* protocol */

    ngx_session_create_main_conf,          /* create main configuration */
    ngx_session_init_main_conf,            /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


ngx_module_t  ngx_session_module = {
    NGX_MODULE_V1,
    &ngx_session_module_ctx,               /* module context */
    ngx_session_commands,                  /* module directives */
    NGX_UDP_MODULE,                        /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_session_init_session(ngx_udp_session_t *s)
{
    ngx_session_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, s->connection->log, 0,
                   "session init session");

    ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_session_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_udp_set_ctx(s, ctx, ngx_session_module);

#if 0
    ctx->s = s;
#endif

    return NGX_OK;
}


static void
ngx_session_process_session(ngx_udp_session_t *s)
{
    u_char                   *p, *last;
    ngx_int_t                 rc;
    ngx_buf_t                *b;
    ngx_session_ctx_t        *ctx;
    ngx_session_main_conf_t  *smcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, s->connection->log, 0,
                   "session process session");

    ctx = ngx_udp_get_module_ctx(s, ngx_session_module);

    p = s->buffer->pos;
    last = s->buffer->last;

    if (last - p < 1) {
        ngx_udp_internal_server_error(s);
        return;
    }

    ctx->type = *p++;

    if (ctx->type != NGX_SESSION_CREATE) {
        if (last - p < 16) {
            ngx_udp_internal_server_error(s);
            return;
        }

        ngx_memcpy(ctx->id, p, 16);

        p += 16;
    }

    b = ngx_create_temp_buf(s->connection->pool, 1024);
    if (b == NULL) {
        ngx_udp_internal_server_error(s);
        return;
    }

    smcf = ngx_udp_get_module_main_conf(s, ngx_session_module);

    switch (ctx->type) {

    case NGX_SESSION_CREATE:
        if (last - p < 6) {
            break;
        }

        ngx_memcpy(&ctx->ip, p, 4);
        p += 4;
        ngx_memcpy(&ctx->port, p, 2);
        p += 2;

        /* TODO */

        rc = ngx_session_create(s, ctx);

        break;

    case NGX_SESSION_DESTROY:

        /* TODO */

        rc = ngx_session_destroy(s, ctx);

        break;

    case NGX_SESSION_SET_PARAM:
        if (last - p < 1) {
            break;
        }

        ctx->param = *p++;

        if (last - p < 1) {
            break;
        }

        ctx->param_val.len = *p++;

        if ((size_t) (last - p) < ctx->param_val.len) {
            break;
        }

        ctx->param_val.data = p;
        p += ctx->param_val.len;

        /* TODO */

        rc = ngx_session_set_param(s, ctx);

        break;

    case NGX_SESSION_GET_PARAM:
        if (last - p < 1) {
            break;
        }

        ctx->param = *p++;

        /* TODO */

        rc = ngx_session_get_param(s, ctx);

        break;

    case NGX_SESSION_SET_VAR:
        if (last - p < 1) {
            break;
        }

        ctx->var_name.len = *p++;

        if ((size_t) (last - p) < ctx->var_name.len) {
            break;
        }

        ctx->var_name.data = p;
        p += ctx->var_name.len;

        if (last - p < 1) {
            break;
        }

        ctx->var_val.len = *p++;

        if ((size_t) (last - p) < ctx->var_val.len) {
            break;
        }

        ctx->var_val.data = p;
        p += ctx->var_val.len;

        /* TODO */

        rc = ngx_session_set_var(s, ctx);

        break;

    case NGX_SESSION_GET_VAR:
    case NGX_SESSION_DEL_VAR:
        if (last - p < 1) {
            break;
        }

        ctx->var_name.len = *p++;

        if ((size_t) (last - p) < ctx->var_name.len) {
            break;
        }

        ctx->var_name.data = p;
        p += ctx->var_name.len;

        /* TODO */

        if (ctx->type == NGX_SESSION_GET_VAR) {
            rc = ngx_session_get_var(s, ctx);

        } else {
            rc = ngx_session_del_var(s, ctx);
        }

        break;
    }

    ngx_udp_close_connection(s->connection);
}


static void *
ngx_session_create_main_conf(ngx_conf_t *cf)
{
    ngx_session_main_conf_t  *smcf;

    smcf = ngx_pcalloc(cf->pool, sizeof(ngx_session_main_conf_t));
    if (smcf == NULL) {
        return NULL;
    }

    return smcf;
}


static char *
ngx_session_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_session_main_conf_t *smcf = conf;

    ngx_rbtree_init(&smcf->rbtree, &smcf->sentinel, ngx_session_insert_value);
    ngx_queue_init(&smcf->queue);

    return NGX_CONF_OK;
}
