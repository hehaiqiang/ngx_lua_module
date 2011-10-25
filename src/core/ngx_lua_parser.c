
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua.h>


#define NGX_LUA_MAX_PARSERS  16


#define NGX_LUA_FUNCTION_START   "return function() local print = print "
#define NGX_LUA_FUNCTION_END     " end"

#define NGX_LUA_PRINT_START      " print([["
#define NGX_LUA_PRINT_END        "]]) "

#define NGX_LUA_EXP_PRINT_START  " print("
#define NGX_LUA_EXP_PRINT_END    ") "


typedef struct {
    ngx_uint_t    stub;
} ngx_lua_parser_conf_t;


static ngx_int_t ngx_lua_parse_default(ngx_lua_thread_t *thr);
static ngx_int_t ngx_lua_parse_lsp(ngx_lua_thread_t *thr);

static void *ngx_lua_parser_create_conf(ngx_cycle_t *cycle);
static char *ngx_lua_parser_init_conf(ngx_cycle_t *cycle, void *conf);


static ngx_core_module_t  ngx_lua_parser_module_ctx = {
    ngx_string("parser"),
    ngx_lua_parser_create_conf,
    ngx_lua_parser_init_conf,
};


ngx_module_t  ngx_lua_parser_module = {
    NGX_MODULE_V1,
    &ngx_lua_parser_module_ctx,            /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_lua_parser_t  ngx_lua_default_parser = {
    ngx_string("default"),
    ngx_lua_parse_default
};


static ngx_lua_parser_t  ngx_lua_lsp_parser = {
    ngx_string("lsp"),
    ngx_lua_parse_lsp
};


static ngx_lua_parser_t  *ngx_lua_parsers[NGX_LUA_MAX_PARSERS];
static ngx_uint_t         ngx_lua_parser_n;


ngx_lua_parser_pt
ngx_lua_parser_find(ngx_log_t *log, ngx_str_t *name)
{
    ngx_uint_t         i;
    ngx_lua_parser_t  *parser;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, 0, "lua parser find");

    for (i = 0; i < ngx_lua_parser_n; i++) {
        parser = ngx_lua_parsers[i];

        if (parser->name.len == name->len
            && ngx_strncmp(parser->name.data, name->data, name->len) == 0)
        {
            return parser->parser;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_lua_parse_default(ngx_lua_thread_t *thr)
{
    size_t   size;
    u_char  *out, *p;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua parse default");

    out = ngx_cpymem(thr->buf->last, NGX_LUA_FUNCTION_START,
                     sizeof(NGX_LUA_FUNCTION_START) - 1);

    size = thr->lsp->last - thr->lsp->pos;
    p = thr->lsp->pos;

    /* UTF-8 BOM */

    if (size >= 3 && p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF) {
        p += 3;
        size -= 3;
    }

    out = ngx_cpymem(out, p, size);

    out = ngx_cpymem(out, NGX_LUA_FUNCTION_END,
                     sizeof(NGX_LUA_FUNCTION_END) - 1);

    thr->buf->last = out;

    return NGX_OK;
}


static ngx_int_t
ngx_lua_parse_lsp(ngx_lua_thread_t *thr)
{
    u_char      *p, ch, *out, *html_start, *lua_start, *lua_end;
    ngx_uint_t   backslash, dquoted, squoted;
    enum {
        sw_start = 0,
        sw_html_block,
        sw_lua_start,
        sw_lua_block_start,
        sw_lua_block,
        sw_lua_block_end,
        sw_lua_exp_block_start,
        sw_lua_exp_block,
        sw_lua_exp_block_end,
        sw_error
    } state;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua parse lsp");

    state = sw_start;

    html_start = NULL;
    lua_start = NULL;
    backslash = 0;
    dquoted = 0;
    squoted = 0;

    out = ngx_cpymem(thr->buf->last, NGX_LUA_FUNCTION_START,
                     sizeof(NGX_LUA_FUNCTION_START) - 1);

    /* TODO */

    for (p = thr->lsp->pos; p < thr->lsp->last; p++) {
        ch = *p;

        switch (state) {

        case sw_start:
            if (ch == '<') {
                html_start = NULL;
                lua_start = p;

                state = sw_lua_start;
                break;
            }

            out = ngx_cpymem(out, NGX_LUA_PRINT_START,
                             sizeof(NGX_LUA_PRINT_START) - 1);

            *out++ = ch;

            html_start = p;
            lua_start = NULL;

            state = sw_html_block;
            break;

        case sw_html_block:
            if (ch == '<') {
                lua_start = p;

                state = sw_lua_start;
                break;
            }

            *out++ = ch;

            break;

        case sw_lua_start:
            if (ch == '%') {
                state = sw_lua_block_start;
                break;
            }

            if (html_start == NULL) {
                html_start = lua_start;
                lua_start = NULL;

                out = ngx_cpymem(out, NGX_LUA_PRINT_START,
                                 sizeof(NGX_LUA_PRINT_START) - 1);
            }

            *out++ = '<';
            *out++ = ch;

            state = sw_html_block;
            break;

        case sw_lua_block_start:
            if (html_start != NULL) {
                html_start = NULL;

                out = ngx_cpymem(out, NGX_LUA_PRINT_END,
                                 sizeof(NGX_LUA_PRINT_END) - 1);
            }

            backslash = 0;
            dquoted = 0;
            squoted = 0;

            if (ch == '=') {
                state = sw_lua_exp_block_start;
                break;
            }

            /* TODO: xxx */

            *out++ = ch;

            state = sw_lua_block;
            break;

        case sw_lua_block:
            switch (ch) {

            case '\'':
                if (backslash || dquoted || squoted) {
                    squoted = 0;
                    backslash = 0;

                } else {
                    squoted = 1;
                }
                break;

            case '\"':
                if (backslash || dquoted || squoted) {
                    dquoted = 0;
                    backslash = 0;

                } else {
                    dquoted = 1;
                }
                break;

            case '\\':
                if (backslash) {
                    backslash = 0;

                } else {
                    backslash = 1;
                }
                break;

            case '%':
                if (backslash || dquoted || squoted) {
                    break;
                }

                lua_end = p;

                state = sw_lua_block_end;
                break;

            default:
                backslash = 0;
                break;
            }

            if (state != sw_lua_block_end) {
                *out++ = ch;
            }

            break;

        case sw_lua_block_end:
            if (ch != '>') {
                /* syntax error */
                state = sw_error;
                break;
            }

            lua_start = NULL;

            state = sw_start;
            break;

        case sw_lua_exp_block_start:
            out = ngx_cpymem(out, NGX_LUA_EXP_PRINT_START,
                             sizeof(NGX_LUA_EXP_PRINT_START) - 1);

            *out++ = ch;

            state = sw_lua_exp_block;
            break;

        case sw_lua_exp_block:
            switch (ch) {

            case '\'':
                if (backslash || dquoted || squoted) {
                    squoted = 0;
                    backslash = 0;

                } else {
                    squoted = 1;
                }
                break;

            case '\"':
                if (backslash || dquoted || squoted) {
                    dquoted = 0;
                    backslash = 0;

                } else {
                    dquoted = 1;
                }
                break;

            case '\\':
                if (backslash) {
                    backslash = 0;

                } else {
                    backslash = 1;
                }
                break;

            case '%':
                if (backslash || dquoted || squoted) {
                    break;
                }

                lua_end = p;

                state = sw_lua_exp_block_end;
                break;

            default:
                backslash = 0;
                break;
            }

            if (state != sw_lua_exp_block_end) {
                *out++ = ch;
            }

            break;

        case sw_lua_exp_block_end:
            if (ch != '>') {
                /* syntax error */
                state = sw_error;
                break;
            }

            /* TODO: xxx */

            out = ngx_cpymem(out, NGX_LUA_EXP_PRINT_END,
                             sizeof(NGX_LUA_EXP_PRINT_END) - 1);

            lua_start = NULL;

            state = sw_start;
            break;

        case sw_error:
            /* TODO: error handling */
            break;
        }
    }

    if (lua_start != NULL) {
        /* TODO: error handling */
    }

    if (html_start != NULL) {
        out = ngx_cpymem(out, NGX_LUA_PRINT_END, sizeof(NGX_LUA_PRINT_END) - 1);
    }

    out = ngx_cpymem(out, NGX_LUA_FUNCTION_END,
                     sizeof(NGX_LUA_FUNCTION_END) - 1);

    thr->buf->last = out;

    return NGX_OK;
}


static void *
ngx_lua_parser_create_conf(ngx_cycle_t *cycle)
{
    ngx_lua_parser_conf_t  *lpcf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua parser create conf");

    lpcf = ngx_pcalloc(cycle->pool, sizeof(ngx_lua_parser_conf_t));
    if (lpcf == NULL) {
        return NULL;
    }

    ngx_lua_parsers[ngx_lua_parser_n++] = &ngx_lua_lsp_parser;
    ngx_lua_parsers[ngx_lua_parser_n++] = &ngx_lua_default_parser;

    return lpcf;
}


static char *
ngx_lua_parser_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "lua parser init conf");

    /* TODO */

    return NGX_CONF_OK;
}