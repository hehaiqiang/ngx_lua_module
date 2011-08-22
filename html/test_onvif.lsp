<%
local print = print
local nginx = nginx
local req = nginx.request

local res = nginx.http({
  method = "POST",
  url = "192.168.1.200:80/onvif/services",
  headers = {
    Content_Type = "text/xml; charset=utf-8",
    Connection = "Keep-Alive",
    Accept_Language = "zh-cn",
    Accept = "*/*",
    User_Agent = "Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)"
  },
  body =
--[[
         '<?xml version="1.0" encoding="utf-8"?>' ..
--]]
--[[
         '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl">' ..
         '<soap:Body>' ..
         '<tds:GetHostname/>' ..
         '</soap:Body>' ..
         '</soap:Envelope>'
--]]
--[[
         '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">' ..
         '<soap:Body>' ..
         '<trt:GetProfiles xmlns:trt="http://www.onvif.org/ver10/media/wsdl">' ..
         '</trt:GetProfiles>' ..
         '</soap:Body>' ..
         '</soap:Envelope>'
--]]
         '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">' ..
         '<soap:Body>' ..
         '<tptz:GetConfiguration xmlns:tptz="http://www.onvif.org/ver10/ptz/wsdl">' ..
         '<PTZConfigurationToken></PTZConfigurationToken>' ..
         '</tptz:GetConfiguration>' ..
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
