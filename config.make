
# Copyright (C) Ngwsx


if [ $NGX_LUA_DLL = YES ]; then
    lua_module_dir="$NGX_OBJS${ngx_dirsep}modules${ngx_dirsep}"
    mkdir -p $lua_module_dir

    ngx_cc="\$(CC) $ngx_compile_opt \$(CFLAGS) -DNGX_DLL=1 \$(ALL_INCS)"

    if [ "$NGX_PLATFORM" != win32 ]; then
        ngx_cc="$ngx_cc -fPIC"
        lua_module_link="-shared -fPIC"
    else
        nginx_lib="$NGX_OBJS${ngx_dirsep}nginx.lib"
        lua_module_def="$ngx_addon_dir/src/core/ngx_lua_module.def"
        lua_module_link="-link -dll -verbose:lib -def:$lua_module_def"
        lua_module_def_libs="ws2_32.lib $nginx_lib"
    fi

    lua_modules=""


    if [ $NGX_LUA_AUTORUN = YES ]; then
        lua_module="$NGX_LUA_AUTORUN_MODULE"
        lua_module_libs="$lua_module_def_libs"
        lua_module_incs=
        lua_module_deps=
        lua_module_srcs="$NGX_LUA_AUTORUN_SRCS"
        . $ngx_addon_dir/auto/make
    fi

    if [ $NGX_LUA_AXIS2C = YES ]; then
        lua_module="$NGX_LUA_AXIS2C_MODULE"
        lua_module_libs="$lua_module_def_libs $AXIS2C_LIBS"
        lua_module_incs=
        lua_module_deps="$ngx_cont$NGX_LUA_AXIS2C_DEPS"
        lua_module_srcs="$NGX_LUA_AXIS2C_SRCS"
        if [ $NGX_LUA_AXIS2C_WS = YES ]; then
            lua_module_srcs="$lua_module_srcs $NGX_LUA_AXIS2C_WS_SRCS"
        fi
        if [ $NGX_LUA_AXIS2C_XML = YES ]; then
            lua_module_srcs="$lua_module_srcs $NGX_LUA_AXIS2C_XML_SRCS"
        fi
        . $ngx_addon_dir/auto/make
    fi

    if [ $NGX_LUA_DAHUA = YES ]; then
        lua_module="$NGX_LUA_DAHUA_MODULE"
        lua_module_libs="$lua_module_def_libs"
        lua_module_incs=
        lua_module_deps=
        lua_module_srcs="$NGX_LUA_DAHUA_SRCS"
        . $ngx_addon_dir/auto/make
    fi

    if [ $NGX_LUA_DBD = YES ]; then
        lua_module="$NGX_LUA_DBD_MODULE"
        lua_module_libs="$lua_module_def_libs"
        lua_module_incs="$NGX_LUA_DBD_INCS"
        lua_module_deps="$ngx_cont$NGX_LUA_DBD_DEPS"
        lua_module_srcs="$NGX_LUA_DBD_MODULE_SRCS"
        . $ngx_addon_dir/auto/make

        if [ $NGX_LUA_DBD_LIBDRIZZLE = YES ]; then
            lua_module="$NGX_LUA_DBD_LIBDRIZZLE_MODULE"
            lua_module_libs="$lua_module_def_libs user32.lib $LIBDRIZZLE_LIBS"
            lua_module_incs="$NGX_LUA_DBD_INCS"
            lua_module_deps="$ngx_cont$NGX_LUA_DBD_DEPS"
            lua_module_srcs="$NGX_LUA_DBD_LIBDRIZZLE_SRCS"
            . $ngx_addon_dir/auto/make
        fi

        if [ $NGX_LUA_DBD_SQLITE3 = YES ]; then
            lua_module="$NGX_LUA_DBD_SQLITE3_MODULE"
            lua_module_libs="$lua_module_def_libs $SQLITE3_LIBS"
            lua_module_incs="$NGX_LUA_DBD_INCS"
            lua_module_deps="$ngx_cont$NGX_LUA_DBD_DEPS"
            lua_module_srcs="$NGX_LUA_DBD_SQLITE3_SRCS"
            . $ngx_addon_dir/auto/make
        fi
    fi

    if [ $NGX_LUA_FILE = YES ]; then
        lua_module="$NGX_LUA_FILE_MODULE"
        lua_module_libs="$lua_module_def_libs"
        lua_module_incs=
        lua_module_deps=
        lua_module_srcs="$NGX_LUA_FILE_SRCS"
        . $ngx_addon_dir/auto/make
    fi

    if [ $NGX_LUA_LOGGER = YES ]; then
        lua_module="$NGX_LUA_LOGGER_MODULE"
        lua_module_libs="$lua_module_def_libs"
        lua_module_incs=
        lua_module_deps=
        lua_module_srcs="$NGX_LUA_LOGGER_SRCS"
        . $ngx_addon_dir/auto/make
    fi

    if [ $NGX_LUA_SMTP = YES ]; then
        lua_module="$NGX_LUA_SMTP_MODULE"
        lua_module_libs="$lua_module_def_libs"
        lua_module_incs=
        lua_module_deps=
        lua_module_srcs="$NGX_LUA_SMTP_SRCS"
        . $ngx_addon_dir/auto/make
    fi

    if [ $NGX_LUA_SOCKET = YES ]; then
        lua_module="$NGX_LUA_SOCKET_MODULE"
        lua_module_libs="$lua_module_def_libs"
        lua_module_incs=
        lua_module_deps=
        lua_module_srcs="$NGX_LUA_SOCKET_SRCS"
        . $ngx_addon_dir/auto/make
    fi

    if [ $NGX_LUA_UTILS = YES ]; then
        lua_module="$NGX_LUA_UTILS_MODULE"
        lua_module_libs="$lua_module_def_libs $SHA1_LIBS"
        lua_module_incs=
        lua_module_deps=
        lua_module_srcs="$NGX_LUA_UTILS_SRCS"
        . $ngx_addon_dir/auto/make
    fi

    if [ $NGX_LUA_HTTP = YES ]; then
        if [ $NGX_LUA_HTTP_REQUEST = YES ]; then
            lua_module="$NGX_LUA_HTTP_REQUEST_MODULE"
            lua_module_libs="$lua_module_def_libs"
            lua_module_incs=
            lua_module_deps=
            lua_module_srcs="$NGX_LUA_HTTP_REQUEST_SRCS"
            . $ngx_addon_dir/auto/make
        fi

        if [ $NGX_LUA_HTTP_RESPONSE = YES ]; then
            lua_module="$NGX_LUA_HTTP_RESPONSE_MODULE"
            lua_module_libs="$lua_module_def_libs"
            lua_module_incs=
            lua_module_deps=
            lua_module_srcs="$NGX_LUA_HTTP_RESPONSE_SRCS"
            . $ngx_addon_dir/auto/make
        fi

        if [ $NGX_LUA_HTTP_SESSION = YES ]; then
            lua_module="$NGX_LUA_HTTP_SESSION_MODULE"
            lua_module_libs="$lua_module_def_libs"
            lua_module_incs=
            lua_module_deps="$ngx_cont$NGX_LUA_HTTP_SESSION_DEPS"
            lua_module_srcs="$NGX_LUA_HTTP_SESSION_SRCS"
            . $ngx_addon_dir/auto/make
        fi

        if [ $NGX_LUA_HTTP_VARIABLE = YES ]; then
            lua_module="$NGX_LUA_HTTP_VARIABLE_MODULE"
            lua_module_libs="$lua_module_def_libs"
            lua_module_incs=
            lua_module_deps=
            lua_module_srcs="$NGX_LUA_HTTP_VARIABLE_SRCS"
            . $ngx_addon_dir/auto/make
        fi
    fi

    if [ $NGX_LUA_TCP = YES ]; then
        if [ $NGX_LUA_TCP_REQUEST = YES ]; then
            lua_module="$NGX_LUA_TCP_REQUEST_MODULE"
            lua_module_libs="$lua_module_def_libs"
            lua_module_incs=
            lua_module_deps=
            lua_module_srcs="$NGX_LUA_TCP_REQUEST_SRCS"
            . $ngx_addon_dir/auto/make
        fi

        if [ $NGX_LUA_TCP_RESPONSE = YES ]; then
            lua_module="$NGX_LUA_TCP_RESPONSE_MODULE"
            lua_module_libs="$lua_module_def_libs"
            lua_module_incs=
            lua_module_deps=
            lua_module_srcs="$NGX_LUA_TCP_RESPONSE_SRCS"
            . $ngx_addon_dir/auto/make
        fi
    fi

    if [ $NGX_LUA_UDP = YES ]; then
        if [ $NGX_LUA_UDP_REQUEST = YES ]; then
            lua_module="$NGX_LUA_UDP_REQUEST_MODULE"
            lua_module_libs="$lua_module_def_libs"
            lua_module_incs=
            lua_module_deps=
            lua_module_srcs="$NGX_LUA_UDP_REQUEST_SRCS"
            . $ngx_addon_dir/auto/make
        fi
    fi


    cat << END                                                >> $NGX_MAKEFILE

modules:	$lua_modules

END

fi
