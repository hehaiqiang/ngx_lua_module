<%

-- This is a lua server page

local print = print
local nginx = nginx
local dbd = nginx.dbd
local log = nginx.log
local req = nginx.req
local resp = nginx.resp

local url = "http://www.126.com/"
local title = "126.com"
%>
<html>
<head>
</head>
<body>
<a href="<%=url%>" target="_blank"><%=title%></a>
<hr>
<table border="1">
<%
local conn = dbd.create("libdrizzle")
if conn then
  if conn:connect("127.0.0.1", 3306, "root", "123456", "mysql") == nginx.OK then
    if conn:query("show databases") == nginx.OK then
%>
<tr>
   <% while conn:column_read() == nginx.OK do %>
<td><%=conn:column_name()%></td>
   <% end %>
</tr>
   <% while conn:row_read() == nginx.OK do %>
<tr>
<%
        repeat
          local value = conn:field_read()
          if value == nginx.ERROR or value == nginx.DONE then break end
%>
<td><%=value%></td>
     <% until false %>
</tr>
<%
      end
    end
  end
  conn:close()
  conn:destroy()
end
%>
</table>
<hr>
<%
-- test the table "log"
--log.error(log.ALERT, "test alert" .. 1 .. 10)
--log.debug(log.DEBUG_HTTP, "test debug http")
--log.error(log.ERR, "test error")
--log.error(log.EMERG, 1000)

-- test the table "req"
print("uri: " .. req.uri .. "<br/>")
print("args: " .. req.args .. "<br/>")
print("host: " .. req.host .. "<br/>")
print("exten: " .. req.exten .. "<br/>")
print("method: " .. req.method .. "<br/>")
if req.referer then print("referer: " .. req.referer .. "<br/>") end
print("user_agent: " .. req.user_agent .. "<br/>")
print("method_name: " .. req.method_name .. "<br/>")
print("request_time: " .. req.request_time .. "ms" .. "<br/>")
print("request_line: " .. req.request_line .. "<br/>")
print("unparsed_uri: " .. req.unparsed_uri .. "<br/>")
print("http_protocol: " .. req.http_protocol .. "<br/>")
local id = req.get["id"] if id then print("id: " .. id .. "<br/>") end
local id = req.get.id if id then print("id: " .. id .. "<br/>") end
local start = req.get["start"] if start then print("start: " .. start .. "<br/>") end
local start = req.get.start if start then print("start: " .. start .. "<br/>") end

-- test the table "resp"
--resp.content_type = "text/html"
--resp.content_type = "text/plain"
resp.write("<hr><hr><hr><hr><hr>")
%>
</body>
</html>
