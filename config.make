
# Copyright (C) Ngwsx


if [ $NGX_LUA_DLL = YES ]; then
    lua_module_dir="$NGX_OBJS${ngx_dirsep}modules${ngx_dirsep}"

    mkdir -p $lua_module_dir

    if [ "$NGX_PLATFORM" != win32 ]; then
        lua_module_link="-shared -fPIC"
    else
        nginx_lib="$NGX_OBJS${ngx_dirsep}nginx.lib"
        lua_module_def="$ngx_addon_dir/src/core/ngx_lua_module.def"
        lua_module_link="-link -dll -verbose:lib -def:$lua_module_def"
        lua_module_def_libs="ws2_32.lib $nginx_lib"
    fi

    ngx_cc="\$(CC) $ngx_compile_opt \$(CFLAGS) -DNGX_DLL=1 \$(ALL_INCS)"

    if [ "$NGX_PLATFORM" != win32 ]; then
        ngx_cc="$ngx_cc -fPIC"
    fi

    lua_modules=""

    lua_module="$NGX_LUA_AXIS2C_MODULE"
    lua_module_libs="$lua_module_def_libs $AXIS2C_LIBS"
    lua_module_incs=
    lua_module_deps="$ngx_cont$NGX_LUA_AXIS2C_DEPS"
    lua_module_srcs=" \
        $NGX_LUA_AXIS2C_SRCS \
        $NGX_LUA_WEBSERVICE_SRCS \
        $NGX_LUA_XML_SRCS"
    . $ngx_addon_dir/auto/make

    lua_module="$NGX_LUA_DAHUA_MODULE"
    lua_module_libs="$lua_module_def_libs"
    lua_module_incs=
    lua_module_deps=
    lua_module_srcs="$NGX_LUA_DAHUA_SRCS"
    . $ngx_addon_dir/auto/make

    lua_module="$NGX_LUA_DBD_MODULE"
    lua_module_libs="$lua_module_def_libs $LIBDRIZZLE_LIBS $SQLITE3_LIBS"
    if [ "$NGX_PLATFORM" = win32 ]; then
        lua_module_libs="$lua_module_libs user32.lib"
    fi
    lua_module_incs="$NGX_LUA_DBD_INCS"
    lua_module_deps="$ngx_cont$NGX_LUA_DBD_DEPS"
    lua_module_srcs="$NGX_LUA_DBD_SRCS"
    . $ngx_addon_dir/auto/make

    lua_module="$NGX_LUA_FILE_MODULE"
    lua_module_libs="$lua_module_def_libs"
    lua_module_incs=
    lua_module_deps=
    lua_module_srcs="$NGX_LUA_FILE_SRCS"
    . $ngx_addon_dir/auto/make

    lua_module="$NGX_LUA_LOGGER_MODULE"
    lua_module_libs="$lua_module_def_libs"
    lua_module_incs=
    lua_module_deps=
    lua_module_srcs="$NGX_LUA_LOGGER_SRCS"
    . $ngx_addon_dir/auto/make

    lua_module="$NGX_LUA_SMTP_MODULE"
    lua_module_libs="$lua_module_def_libs"
    lua_module_incs=
    lua_module_deps=
    lua_module_srcs="$NGX_LUA_SMTP_SRCS"
    . $ngx_addon_dir/auto/make

    lua_module="$NGX_LUA_SOCKET_MODULE"
    lua_module_libs="$lua_module_def_libs"
    lua_module_incs=
    lua_module_deps=
    lua_module_srcs="$NGX_LUA_SOCKET_SRCS"
    . $ngx_addon_dir/auto/make

    lua_module="$NGX_LUA_UTILS_MODULE"
    lua_module_libs="$lua_module_def_libs"
    lua_module_incs=
    lua_module_deps=
    lua_module_srcs="$NGX_LUA_UTILS_SRCS"
    . $ngx_addon_dir/auto/make

    lua_module="$NGX_LUA_HTTP_REQUEST_MODULE"
    lua_module_libs="$lua_module_def_libs"
    lua_module_incs=
    lua_module_deps=
    lua_module_srcs="$NGX_LUA_HTTP_REQUEST_SRCS"
    . $ngx_addon_dir/auto/make

    lua_module="$NGX_LUA_HTTP_RESPONSE_MODULE"
    lua_module_libs="$lua_module_def_libs"
    lua_module_incs=
    lua_module_deps=
    lua_module_srcs="$NGX_LUA_HTTP_RESPONSE_SRCS"
    . $ngx_addon_dir/auto/make

    lua_module="$NGX_LUA_HTTP_SESSION_MODULE"
    lua_module_libs="$lua_module_def_libs"
    lua_module_incs=
    lua_module_deps=
    lua_module_srcs="$NGX_LUA_HTTP_SESSION_SRCS"
    . $ngx_addon_dir/auto/make

    lua_module="$NGX_LUA_HTTP_VARIABLE_MODULE"
    lua_module_libs="$lua_module_def_libs"
    lua_module_incs=
    lua_module_deps=
    lua_module_srcs="$NGX_LUA_HTTP_VARIABLE_SRCS"
    . $ngx_addon_dir/auto/make

    cat << END                                                >> $NGX_MAKEFILE

modules:	$lua_modules

END

fi
