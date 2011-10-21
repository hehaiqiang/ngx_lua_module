<%
local print = print
local nginx = nginx
local file = nginx.file
local req = nginx.http_srv.request

local f, errstr = file.open('c:/test.txt')
if not f then print(errstr) return end

local data, errstr = f:read()
if not data then print(errstr) end

print(data or '')
print('<hr>')

data = data or 'test'
local n, errstr = f:write(data)
if not n then print(errstr) f:close() return end

f:close()
%>
<html>
<head>
</head>
<body>
<hr>
test file api
<hr>
request time: <%=req.request_time%>ms
</body>
</html>
