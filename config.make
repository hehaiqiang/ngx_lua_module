
# Copyright (C) Ngwsx


if [ $NGX_LUA_DLL = YES ]; then
    ngx_so_dir="$NGX_OBJS${ngx_dirsep}modules${ngx_dirsep}"

    mkdir -p $ngx_so_dir

    if [ "$NGX_PLATFORM" != win32 ]; then
        ngx_lib=" -shared -fPIC"
    else
        ngx_lib=" \
            -link -dll -verbose:lib \
            -def:$ngx_addon_dir/src/core/ngx_lua_module.def \
            ws2_32.lib $NGX_OBJS${ngx_dirsep}nginx.lib"
    fi

    ngx_cc="\$(CC) $ngx_compile_opt \$(CFLAGS) -DNGX_DLL=1 \$(ALL_INCS)"

    if [ "$NGX_PLATFORM" != win32 ]; then
        ngx_cc="$ngx_cc -fPIC"
    fi

    NGX_LUA_MODULE_SRCS=" \
        $NGX_LUA_DAHUA_MODULE_SRCS \
        $NGX_LUA_FILE_MODULE_SRCS \
        $NGX_LUA_LOGGER_MODULE_SRCS \
        $NGX_LUA_SMTP_MODULE_SRCS \
        $NGX_LUA_SOCKET_MODULE_SRCS \
        $NGX_LUA_HTTP_REQUEST_MODULE_SRCS \
        $NGX_LUA_HTTP_RESPONSE_MODULE_SRCS \
        $NGX_LUA_HTTP_SESSION_MODULE_SRCS \
        $NGX_LUA_HTTP_VARIABLE_MODULE_SRCS"

    ngx_sos=""

    for ngx_src in $NGX_LUA_MODULE_SRCS
    do
        ngx_obj="addon/`basename \`dirname $ngx_src\``"

        ngx_obj=`echo $ngx_obj/\`basename $ngx_src\` \
            | sed -e "s/\//$ngx_regex_dirsep/g"`

        ngx_obj=`echo $ngx_obj \
            | sed -e "s#^\(.*\.\)cpp\\$#$ngx_objs_dir\1$ngx_objext#g" \
                  -e "s#^\(.*\.\)cc\\$#$ngx_objs_dir\1$ngx_objext#g" \
                  -e "s#^\(.*\.\)c\\$#$ngx_objs_dir\1$ngx_objext#g" \
                  -e "s#^\(.*\.\)S\\$#$ngx_objs_dir\1$ngx_objext#g"`

        ngx_src=`echo $ngx_src | sed -e "s/\//$ngx_regex_dirsep/g"`

        cat << END                                            >> $NGX_MAKEFILE

$ngx_obj:	\$(ADDON_DEPS)$ngx_cont$ngx_src
	$ngx_cc$ngx_tab$ngx_objout$ngx_obj$ngx_tab$ngx_src$NGX_AUX

END

        ngx_so=`basename $ngx_obj`

        ngx_so=`echo $ngx_so \
            | sed -e "s#^\(.*\.\)$ngx_objext\\$#$ngx_so_dir\1so#g"`

        cat << END                                            >> $NGX_MAKEFILE

$ngx_so:	$ngx_obj$ngx_spacer
	\$(LINK) ${ngx_long_start}${ngx_binout}$ngx_so$ngx_long_cont$ngx_obj$ngx_lib
${ngx_long_end}

END

        ngx_sos="$ngx_sos$ngx_cont$ngx_so"
    done

        cat << END                                            >> $NGX_MAKEFILE

modules:	$ngx_sos

END

fi
