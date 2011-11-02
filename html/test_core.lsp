<%
local print = print
local nginx = nginx
local utils = nginx.utils
local req = nginx.http_srv.request

local uri = 'id=你好&title=世界'

local escaped_uri, errstr = utils.escape_uri(uri)
if not escaped_uri then print(errstr) return end
print('URI escape test<br>', uri, '<br>', escaped_uri, '<hr>')

local unescaped_uri, errstr = utils.unescape_uri(escaped_uri)
if not unescaped_uri then print(errstr) return end
print('URI unescape test<br>', escaped_uri, '<br>', unescaped_uri, '<hr>')

local str = 'testtesttesttesttesttesttesttesttesttesttesttest'

local encoded_base64, errstr = utils.encode_base64(str)
if not encoded_base64 then print(errstr) return end
print('BASE64 encode test<br>', str, '<br>', encoded_base64, '<hr>')

local decoded_base64, errstr = utils.decode_base64(encoded_base64)
if not decoded_base64 then print(errstr) return end
print('BASE64 decode test<br>', encoded_base64, '<br>', decoded_base64, '<hr>')

local crc16, errstr = utils.crc16(str)
if not crc16 then print(errstr) return end
print('CRC16 test<br>', str, '<br>', crc16, '<hr>')

local crc32, errstr = utils.crc32(str)
if not crc32 then print(errstr) return end
print('CRC32 test<br>', str, '<br>', crc32, '<hr>')

local murmur_hash2, errstr = utils.murmur_hash2(str)
if not murmur_hash2 then print(errstr) return end
print('MURMURHASH2 test<br>', str, '<br>', murmur_hash2, '<hr>')

local md5, errstr = utils.md5(str)
if not md5 then print(errstr) return end
print('MD5 test<br>', str, '<br>', md5, '<hr>')

local sha1, errstr = utils.sha1(str)
if not sha1 then print(errstr) return end
print('SHA1 test<br>', str, '<br>', sha1, '<hr>')

utils.sleep('500ms')
utils.sleep('3s')
utils.sleep(500)
utils.sleep(2000)
utils.sleep('6s500ms')
%>
<html>
<head>
</head>
<body>
request time: <%=req.request_time%>ms
</body>
</html>
