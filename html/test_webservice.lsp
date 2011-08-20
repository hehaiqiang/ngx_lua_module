<%
local print = print
local nginx = nginx
local axis2c = nginx.axis2c
local req = nginx.request

local body = axis2c.serialize({
  header = {},
  body = {}
})

local res = nginx.http({
  method = "POST",
  version = "1.1",
  url = "www.webxml.com.cn/WebServices/WeatherWebService.asmx",
  headers = {
    Content_Type = "text/xml; charset=utf-8",
    Connection = "Keep-Alive",
    Accept_Language = "zh-cn",
    Accept = "*/*",
    User_Agent = "Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)"
  },
  body = --[[body--]]
         '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">' ..
         '<soap:Body>' ..
         '<getSupportCity xmlns="http://WebXml.com.cn/">' ..
         '<byProvinceName></byProvinceName>' ..
         '</getSupportCity>' ..
         '</soap:Body>' ..
         '</soap:Envelope>'
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
<%=res.body or ""%>
<hr>
request_time: <%=req.request_time%>ms
</body>
</html>
