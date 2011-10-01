<%
local print = print
local nginx = nginx
local dahua = nginx.dahua
local req = nginx.request

local dh, errstr = dahua.open('doc4gz.gnway.net:37777')
if not dh then print(errstr) return end

local result, errstr = dh:login('admin', 'admin')
if not result then print(errstr) dh:close() return end

--local result, errstr = dh:ptz(dahua.PTZ_RIGHT, 0, 0, 1)
--if not result then print(errstr) dh:close() return end

--local result, errstr = dh:video(1, 1)
--if not result then print(errstr) dh:close() return end

dh:close()
%>
<html>
<head>
</head>
<body>
<hr>
request time: <%=req.request_time%>ms
</body>
</html>
