
# Copyright (C) Ngwsx


rm -fr ./build/conf
rm -fr ./build/html
rm -fr ./build/logs
rm -fr ./build/temp

mkdir ./build/conf
mkdir ./build/logs
mkdir ./build/temp

cp -fr conf/nginx-unix.conf ./build/conf/nginx.conf
cp -fr conf/mime.types ./build/conf/mime.types
cp -fr conf/lua_load_modules.conf ./build/conf/lua_load_modules.conf

cp -fr html ./build
