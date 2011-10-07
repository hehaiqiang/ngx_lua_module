
# Copyright (C) Ngwsx


if [ $NGX_LUA_DLL = YES ]; then
    mkdir -p $NGX_OBJS/modules

    ngx_cc="\$(CC) $ngx_compile_opt \$(CFLAGS) -DNGX_DLL=1 \$(ALL_INCS)"

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

        ngx_so_dir="modules/"

        ngx_soext="so"

        ngx_so=`basename $ngx_obj`

        ngx_so=`echo $ngx_so \
            | sed -e "s#^\(.*\.\)obj\\$#$ngx_so_dir\1$ngx_soext#g"`

        cat << END                                            >> $NGX_MAKEFILE

$NGX_OBJS${ngx_dirsep}$ngx_so:	$ngx_obj$ngx_spacer
	\$(LINK) ${ngx_long_start}${ngx_binout}$NGX_OBJS${ngx_dirsep}$ngx_so$ngx_long_cont$ngx_obj -link -dll -verbose:lib -def:$ngx_addon_dir/src/modules/ngx_lua_module.def ws2_32.lib $NGX_OBJS${ngx_dirsep}nginx.lib
	$ngx_rcc
${ngx_long_end}

END
    done
fi
