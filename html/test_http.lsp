<%
local print = print
local nginx = nginx
local req = nginx.http_srv.request

local res = nginx.utils.http({
  url = 'www.nginx.org/index.html'
})
if res.status == nginx.ERROR then
  print('error')
  return
end
%>
<html>
<head>
</head>
<body>
<hr>
<%=res.status or ''%>
<hr>
<table border='1'>
<% for k,v in pairs(res.headers) do %>
<tr><td><%=k%></td><td><%=v%></td></tr>
<% end %>
</table>
<hr>
<%=#res.body%>
<hr>
<%=res.body or ''%>
<hr>
request_time: <%=req.request_time%>ms
</body>
</html>
