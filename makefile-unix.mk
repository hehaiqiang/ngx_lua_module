
# Copyright (C) Ngwsx


NGINX_BIN=nginx
NGINX_DIR=../../nginx
ADDON_DIR=$(PWD)

include $(NGINX_DIR)/unix.args

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

include $(NGINX_DIR)/unix.mk

modules:
	(cd $(NGINX_DIR); \
	$(MAKE) -f $(ADDON_DIR)/build/Makefile modules; \
	cd $(ADDON_DIR));
