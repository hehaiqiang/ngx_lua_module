
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_LUA_DLFCN_H_INCLUDED_
#define _NGX_LUA_DLFCN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_WIN32)

#define ngx_lua_dlopen(name)        LoadLibrary(name)
#define ngx_lua_dlopen_n            "LoadLibrary()"

#define ngx_lua_dlclose(handle)     FreeLibrary(handle)

#define ngx_lua_dlsym(handle, sym)  GetProcAddress(handle, sym)
#define ngx_lua_dlsym_n             "GetProcAddress()"

#define ngx_lua_dlerror()           ""

#else

#include <dlfcn.h>

#define ngx_lua_dlopen(name)        dlopen(name, RTLD_LAZY)
#define ngx_lua_dlopen_n            "dlopen()"

#define ngx_lua_dlclose(handle)     dlclose(handle)

#define ngx_lua_dlsym(handle, sym)  dlsym(handle, sym)
#define ngx_lua_dlsym_n             "dlsym()"

#define ngx_lua_dlerror()           dlerror()

#endif


#endif /* _NGX_LUA_DLFCN_H_INCLUDED_ */
