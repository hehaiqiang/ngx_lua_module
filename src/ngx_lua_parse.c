
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua.h>


#define NGX_LUA_FUNCTION_START   "return function() local print = print "
#define NGX_LUA_FUNCTION_END     " end"

#define NGX_LUA_PRINT_START      " print([["
#define NGX_LUA_PRINT_END        "]]) "

#define NGX_LUA_EXP_PRINT_START  " print("
#define NGX_LUA_EXP_PRINT_END    ") "


ngx_int_t
ngx_lua_parse(ngx_lua_thread_t *thr)
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

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, thr->log, 0, "lua parse");

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