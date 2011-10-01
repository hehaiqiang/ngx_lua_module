<%
local print = print
local nginx = nginx
local var = nginx.variable
local array = {
  --var.arg_PARAMETER or "",
  args = var.args or "",
  binary_remote_addr = var.binary_remote_addr or "",
  body_bytes_sent = var.body_bytes_sent or "",
  content_length = var.content_length or "",
  content_type = var.content_type or "",
  --var.cookie_COOKIE or "",
  document_root = var.document_root or "",
  document_uri = var.document_uri or "",
  host = var.host or "",
  hostname = var.hostname or "",
  --var.http_HEADER or "",
  user_agent = var.http_user_agent or "",
  is_args = var.is_args or "",
  limit_rate = var.limit_rate or "",
  nginx_version = var.nginx_version or "",
  query_string = var.query_string or "",
  remote_addr = var.remote_addr or "",
  remote_port = var.remote_port or "",
  remote_user = var.remote_user or "",
  request_filename = var.request_filename or "",
  request_body = var.request_body or "",
  request_body_file = var.request_body_file or "",
  request_completion = var.request_completion or "",
  request_method = var.request_method or "",
  request_uri = var.request_uri or "",
  scheme = var.scheme or "",
  server_addr = var.server_addr or "",
  server_name = var.server_name or "",
  server_port = var.server_port or "",
  server_protocol = var.server_protocol or "",
  uri = var.uri or ""
}
%>
<html>
<head>
</head>
<body>
<%=#array%>
<hr>
<table border="1">
<% for k,v in pairs(array) do %>
<tr><td><%=k%></td><td><%=v%></td></tr>
<% end %>
</table>
</body>
</html>
