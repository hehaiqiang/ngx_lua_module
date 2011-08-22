<%
local print = print
local nginx = nginx
local req = nginx.request

local res = nginx.http({
  version = "1.0",
  url = "192.168.1.200:80/mjpg/1/video.mjpg",
  headers = {
    Authorization = "Basic " .. nginx.encode_base64("root:pass"),
    Connection = "close",
    Cache_Control = "no-cache"
  }
})
if res.status == nginx.ERROR then
  print("error")
  return
end
%>
<html>
<head>
</head>
<body>
<hr>
<%=res.status or ""%>
<hr>
<table border="1">
<% for k,v in pairs(res.headers) do %>
<tr><td><%=k%></td><td><%=v%></td></tr>
<% end %>
</table>
<hr>
<%res.body = res.body or ""%>
<%=#res.body%>
<hr>
<!--
<%=res.body or ""%>
-->
<hr>
request_time: <%=req.request_time%>ms
</body>
</html>
