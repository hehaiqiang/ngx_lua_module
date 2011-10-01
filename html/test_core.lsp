<%
local print = print
local nginx = nginx
local req = nginx.request

local uri = 'id=你好&title=世界'

local escaped_uri, errstr = nginx.escape_uri(uri)
if not escaped_uri then print(errstr) return end
print('URI escape test<br>', uri, '<br>', escaped_uri, '<hr>')

local unescaped_uri, errstr = nginx.unescape_uri(escaped_uri)
if not unescaped_uri then print(errstr) return end
print('URI unescape test<br>', escaped_uri, '<br>', unescaped_uri, '<hr>')

local str = 'testtesttesttesttesttesttesttesttesttesttesttest'

local encoded_base64, errstr = nginx.encode_base64(str)
if not encoded_base64 then print(errstr) return end
print('BASE64 encode test<br>', str, '<br>', encoded_base64, '<hr>')

local decoded_base64, errstr = nginx.decode_base64(encoded_base64)
if not decoded_base64 then print(errstr) return end
print('BASE64 decode test<br>', encoded_base64, '<br>', decoded_base64, '<hr>')

local crc16, errstr = nginx.crc16(str)
if not crc16 then print(errstr) return end
print('CRC16 test<br>', str, '<br>', crc16, '<hr>')

local crc32, errstr = nginx.crc32(str)
if not crc32 then print(errstr) return end
print('CRC32 test<br>', str, '<br>', crc32, '<hr>')

local murmur_hash2, errstr = nginx.murmur_hash2(str)
if not murmur_hash2 then print(errstr) return end
print('MURMURHASH2 test<br>', str, '<br>', murmur_hash2, '<hr>')

local md5, errstr = nginx.md5(str)
if not md5 then print(errstr) return end
print('MD5 test<br>', str, '<br>', md5, '<hr>')

local sha1, errstr = nginx.sha1(str)
if not sha1 then print(errstr) return end
print('SHA1 test<br>', str, '<br>', sha1, '<hr>')
%>
<html>
<head>
</head>
<body>
request time: <%=req.request_time%>ms
</body>
</html>
