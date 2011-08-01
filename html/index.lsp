<%

-- This is a lua server page

local print = print
local nginx = nginx
local dbd = nginx.dbd
local log = nginx.log
local req = nginx.req
local resp = nginx.resp
local var = nginx.var

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
print("<hr>")
--log.error(log.ALERT, "test alert" .. 1 .. 10)
--log.debug(log.DEBUG_HTTP, "test debug http")
--log.error(log.ERR, "test error")
--log.error(log.EMERG, 1000)

-- test the table "req"
print("<hr>")
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

-- test the table "req.headers"
print("<hr>")
print("Host: " .. req.headers.host .. "<br/>")
print("User-Agent: " .. req.headers.user_agent .. "<br/>")

-- test the table "req.cookies"
print("<hr>")

-- test the table "req.get"
print("<hr>")
local id = req.get["id"] if id then print("id: " .. id .. "<br/>") end
local id = req.get.id if id then print("id: " .. id .. "<br/>") end
local start = req.get["start"] if start then print("start: " .. start .. "<br/>") end
local start = req.get.start if start then print("start: " .. start .. "<br/>") end

-- test the table "req.post"
local message = req.post.message if message then print("message: " .. message .. "<br/>") end
print("<hr>")

-- test the table "resp"
print("<hr>")
--resp.content_type = "text/html"
--resp.content_type = "text/plain"
resp.write("xxxxxxxxxx")

-- test the table "var"
print("<hr>")
--print(var.arg_PARAMETER .. "<br/>")
local args = var.args if args then print("args: " .. args .. "<br/>") end
--print(var.binary_remote_addr .. "<br/>")
print("body_bytes_sent: " .. var.body_bytes_sent .. "<br/>")
local content_length = var.content_length if content_length then print("content_length: " .. content_length .. "<br/>") end
local content_type = var.content_type if content_type then print("content_type: " .. content_type .. "<br/>") end
--print(var.cookie_COOKIE .. "<br/>")
print("document_root: " .. var.document_root .. "<br/>")
print("document_uri: " .. var.document_uri .. "<br/>")
print("host: " .. var.host .. "<br/>")
print("hostname: " .. var.hostname .. "<br/>")
--print(var.http_HEADER .. "<br/>")
print("is_args: " .. var.is_args .. "<br/>")
print("limit_rate: " .. var.limit_rate .. "<br/>")
print("nginx_version: " .. var.nginx_version .. "<br/>")
local query_string = var.query_string if query_string then print("query_string: " .. query_string .. "<br/>") end
print("remote_addr: " .. var.remote_addr .. "<br/>")
print("remote_port: " .. var.remote_port .. "<br/>")
--print("remote_user: " .. var.remote_user .. "<br/>")
print("request_filename: " .. var.request_filename .. "<br/>")
--print("request_body: " .. var.request_body .. "<br/>")
--print("request_body_file: " .. var.request_body_file .. "<br/>")
print("request_completion: " .. var.request_completion .. "<br/>")
print("request_method: " .. var.request_method .. "<br/>")
print("request_uri: " .. var.request_uri .. "<br/>")
print("scheme: " .. var.scheme .. "<br/>")
print("server_addr: " .. var.server_addr .. "<br/>")
print("server_name: " .. var.server_name .. "<br/>")
print("server_port: " .. var.server_port .. "<br/>")
print("server_protocol: " .. var.server_protocol .. "<br/>")
print("uri: " .. var.uri .. "<br/>")
%>
<form action="index.lsp" method="post">
<input type="text" name="title"/>
<input type="text" name="message"/>
<input type="submit" value="submit"/>
</form>
</body>
</html>
