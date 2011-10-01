
# Copyright (C) Ngwsx


NGINX_BIN=nginx
NGINX_DIR=../../nginx
ADDON_DIR=../addon/ngx_lua_module

include ../../nginx/win32.args

CONF_ARGS= \
	$(CORE_CONF_ARGS) \
	--with-file-aio \
	--with-debug \
	$(PCRE_CONF_ARGS) \
	$(SHA1_CONF_ARGS) \
	$(HTTP_CONF_ARGS) \
	--without-http-cache \
	--without-http_gzip_module \
	--without-http_auth_basic_module \
	--without-http_proxy_module \
	--without-http_fastcgi_module \
	--without-http_uwsgi_module \
	--without-http_scgi_module \
	--without-http_memcached_module \
	--add-module=$(ADDON_DIR)

include ../../nginx/win32.mk
