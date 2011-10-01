<%
local print = print
local nginx = nginx
local req = nginx.request
local smtp = nginx.smtp

local rc, errstr = smtp.send({
  host = 'smtp.126.com',
  user = 'ngxteam@126.com',
  password = '20082011',
  from = 'ngxteam@126.com',
  to = {
    'ngwsx2008@126.com',
    'hqhe1982@126.com',
    '184815157@qq.com',
    'hqhe1982@hotmail.com'
  },
  subject = 'ngx_lua_module',
  content = 'ngx_lua_module test smtp'
})

if not rc then print(errstr) end
%>
<html>
<head>
</head>
<body>
<hr>
test smtp api
<hr>
request time: <%=req.request_time%>ms
</body>
</html>
