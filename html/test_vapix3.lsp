<%
local print = print
local nginx = nginx
local file = nginx.file
local req = nginx.request

--192.168.1.200:80/mjpg/1/video.mjpg

local res, errstr = nginx.http({
  url = "192.168.1.200/axis-cgi/jpg/image.cgi?resolution=704x576&camera=1&compression=30",
  headers = {
    authorization = "Basic " .. nginx.encode_base64("root:pass"),
    connection = "Keep-Alive"
  }
})

if not res then print(errstr) return end

print('<hr>', res.status, '<hr>')
--print('<hr>', res.body, '<hr>')

print('<table border="1">')
for k,v in pairs(res.headers) do
  print('<tr><td>', k, '</td><td>', v, '</td></tr>')
end
print('</table>')

local f = file.open("c:/temp/test.jpg", file.WRONLY, file.TRUNCATE, file.DEFAULT_ACCESS)
f:write(res.body)
f:close()
%>
<html>
<head>
</head>
<body>
<hr>
request time: <%=req.request_time%>ms
</body>
</html>
