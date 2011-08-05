<%
local print = print
local nginx = nginx
local req = nginx.request

local get_req_members = function()
  return {
    uri = req.uri,
    args = req.args,
    host = req.host,
    exten = req.exten,
    method = req.method,
    referer = req.referer,
    user_agent = req.user_agent,
    method_name = req.method_name,
    request_time = req.request_time .. "ms",
    request_line = req.request_line,
    unparsed_uri = req.unparsed_uri,
    http_protocol = req.http_protocol
  }
end

function get_headers_members()
  local headers = req.headers
  return {
    host = headers.host,
    user_agent = headers.user_agent
  }
end
%>
<html>
<head>
</head>
<body>
<table border="1">
<% for k,v in pairs(get_req_members()) do %>
<tr><td><%=k%></td><td><%=v%></td></tr>
<% end %>
</table>
<hr>
<table border="1">
<% for k,v in pairs(get_headers_members()) do %>
<tr><td><%=k%></td><td><%=v%></td></tr>
<% end %>
</table>
<%
-- TODO: test the table "req.cookies"
%>
<hr>
<%
local one = req["one"] or 1
local two = req.two or 2
local three = req.get["three"] or 3
local four = req.get.four or 4
%>
hello, <%=one%><%=two%><%=three%><%=four%>!
</body>
</html>
