
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_LUA_AXIS2C_H_INCLUDED_
#define _NGX_LUA_AXIS2C_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#if (NGX_WIN32)
#undef S_IWRITE
#endif


#include <axis2_util.h>
#include <axutil_error_default.h>
#include <axiom.h>
#include <axiom_soap.h>


#if !(NGX_WIN32)
#define ngx_stdcall
#endif


axutil_allocator_t *ngx_lua_axis2c_allocator_create(ngx_http_request_t *r);

axutil_log_t *ngx_lua_axis2c_log_create(ngx_http_request_t *r);


#endif /* _NGX_LUA_AXIS2C_H_INCLUDED_ */