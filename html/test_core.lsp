<%
local nginx = nginx
%>
<html>
<head>
</head>
<body>
<%
local uri = "id=ÄãºÃ&title=ÊÀ½ç"
local escaped_uri = nginx.escape_uri(uri)
local unescaped_uri = nginx.unescape_uri(escaped_uri)
local str = "dsdsdtdkslddfsdfdffdfsdfsdfweijqawlkrklekefwklksldksksd"
local encoded_base64 = nginx.encode_base64(str)
local decoded_base64 = nginx.decode_base64(encoded_base64)
local crc16 = nginx.crc16(str) or "crc16 error";
local crc32 = nginx.crc32(str) or "crc32 error";
local murmur_hash2 = nginx.murmur_hash2(str) or "murmur_hash2 error"
local md5 = nginx.md5(str) or "md5 error"
local sha1 = nginx.sha1(str) or "sha1 error"
%>
URI escape test<br/><%=uri%><br/><%=escaped_uri%>
<hr>
URI unescape test<br/><%=escaped_uri%><br/><%=unescaped_uri%>
<hr>
BASE64 encode test<br/><%=str%><br/><%=encoded_base64%>
<hr>
BASE64 decode test<br/><%=encoded_base64%><br/><%=decoded_base64%>
<hr>
CRC16 test<br/><%=str%><br/><%=crc16%>
<hr>
CRC32 test<br/><%=str%><br/><%=crc32%>
<hr>
MURMURHASH2 test<br/><%=str%><br/><%=murmur_hash2%>
<hr>
MD5 test<br/><%=str%><br/><%=md5%>
<hr>
SHA1 test<br/><%=str%><br/><%=sha1%>
</body>
</html>
