<%
local print = print
local nginx = nginx
local axis2c = nginx.axis2c
local req = nginx.request
local resp = nginx.response

--resp.content_type = "text/plain"

local body = axis2c.serialize({
  body = {
    name = "getSupportCity",
    uri = "http://WebXml.com.cn/",
    attributes = {
      attr1 = nil,
      attr2 = nil
    },
    children = {
      { name = "byProvinceName" }
    }
  }
})

print(body or "")
--do return end

local res = nginx.http({
  method = "POST",
  url = "www.webxml.com.cn/WebServices/WeatherWebService.asmx",
  headers = {
    Content_Type = "text/xml; charset=utf-8",
    Connection = "Keep-Alive",
    Accept_Language = "zh-cn",
    Accept = "*/*",
    User_Agent = "Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)"
  },
  body = body
})

if res.status == nginx.ERROR then
  print("error")
  return
end

local res_table = axis2c.parse(res.body)
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
<hr>
<%=#res_table%>
<br>
<%=res_table.uri%>
<br>
<%=res_table.prefix%>
<hr>
<%=res_table.body.name%>
<br>
<%=res_table.body.uri%>
<br>
<%=res_table.body.prefix%>
<br>
<%=#res_table.body.children%>
<hr>
<%
local elem = res_table.body.children[1]
print(elem.name .. "<br>")
print(#elem.children .. "<br>")
for i,v in ipairs(elem.children) do
  print(v.text .. "<br>")
end
%>
<hr>
request_time: <%=req.request_time%>ms
</body>
</html>
