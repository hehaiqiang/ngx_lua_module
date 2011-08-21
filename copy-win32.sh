
# Copyright (C) Ngwsx


rm -fr ./build/conf
rm -fr ./build/html
rm -fr ./build/logs
rm -fr ./build/temp

mkdir ./build/conf
mkdir ./build/logs
mkdir ./build/temp

cp -fr conf/nginx-win32.conf ./build/conf/nginx.conf
cp -fr conf/mime.types ./build/conf/mime.types

cp -fr html ./build

cp -fr ../../../lib/axis2c/libs/win32/*.dll ./build
