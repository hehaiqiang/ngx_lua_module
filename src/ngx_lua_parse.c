
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lua_module.h>


#if 0
#define NGX_LUA_OUTPUT_START  "ngx_lua_output_str([["
#else
#define NGX_LUA_OUTPUT_START  "print([["
#endif
#define NGX_LUA_OUTPUT_END    "]]);"


ngx_int_t
ngx_lua_parse(ngx_http_request_t *r, ngx_lua_ctx_t *ctx)
{
    size_t            size;
    u_char           *p, ch, *out, *html_start, *lua_start, *lua_end;
    ssize_t           n;
    ngx_fd_t          fd;
    ngx_err_t         err;
    ngx_uint_t        backslash, dquoted, squoted;
    ngx_file_info_t   fi;
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

    fd = ngx_open_file(ctx->path.data, NGX_FILE_RDONLY, NGX_FILE_OPEN,
                       NGX_FILE_DEFAULT_ACCESS);
    if (fd == NGX_INVALID_FILE) {
        err = ngx_errno;
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, err,
                      ngx_open_file_n " \"%s\" failed", ctx->path.data);

        switch (err) {
        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:
            return NGX_HTTP_NOT_FOUND;
        case NGX_EACCES:
            return NGX_HTTP_FORBIDDEN;
        default:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    size = (size_t) ngx_file_size(&fi);

    ctx->lsp = ngx_create_temp_buf(r->pool, size);
    if (ctx->lsp == NULL) {
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    n = ngx_read_fd(fd, ctx->lsp->pos, size);
    if (n == NGX_FILE_ERROR || n != (ssize_t) size) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_read_fd_n " failed");
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    ctx->lsp->last += n;

    ngx_close_file(fd);

    size = ngx_max(size * 2, ngx_pagesize);

    ctx->buf = ngx_create_temp_buf(r->pool, size);
    if (ctx->buf == NULL) {
        return NGX_ERROR;
    }

    state = sw_start;

    html_start = NULL;
    lua_start = NULL;
    backslash = 0;
    dquoted = 0;
    squoted = 0;

    out = ngx_cpymem(ctx->buf->last, "return function()\n",
                     sizeof("return function()\n") - 1);

    /* TODO */

    for (p = ctx->lsp->pos; p < ctx->lsp->last; p++) {
        ch = *p;

        switch (state) {

        case sw_start:
            if (ch == '<') {
                html_start = NULL;
                lua_start = p;

                state = sw_lua_start;
                break;
            }

            out = ngx_cpymem(out, NGX_LUA_OUTPUT_START,
                             sizeof(NGX_LUA_OUTPUT_START) - 1);

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

                out = ngx_cpymem(out, NGX_LUA_OUTPUT_START,
                                 sizeof(NGX_LUA_OUTPUT_START) - 1);
            }

            *out++ = '<';
            *out++ = ch;

            state = sw_html_block;
            break;

        case sw_lua_block_start:
            if (html_start != NULL) {
                html_start = NULL;

                out = ngx_cpymem(out, NGX_LUA_OUTPUT_END,
                                 sizeof(NGX_LUA_OUTPUT_END) - 1);
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

            /* TODO: xxx */

            out = ngx_cpymem(out, "print(", sizeof("print(") - 1);

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

            out = ngx_cpymem(out, ");", sizeof(");") - 1);

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
        out = ngx_cpymem(out, NGX_LUA_OUTPUT_END,
                         sizeof(NGX_LUA_OUTPUT_END) - 1);
    }

    out = ngx_cpymem(out, "\nend", sizeof("\nend") - 1);

    ctx->buf->last = out;

    return NGX_OK;
}
