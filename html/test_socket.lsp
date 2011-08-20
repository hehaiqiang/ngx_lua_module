<%
local nginx = nginx
local resp = nginx.response
local socket = nginx.socket
resp.content_type = "text/html"
%>
<% local s = socket.open("www.nginx.org:80") %>
<%=s:send("GET / HTTP/1.1\r\nHost: www.nginx.org\r\n\r\n") or "send error"%>
<hr>
<% local n,res = s:recv() %>
<%=n or "recv error"%>
<hr>
<%=res or "recv error"%>
<hr>
<% n,res = s:recv() %>
<%=n or "recv error"%>
<hr>
<%=res or "recv error"%>
<hr>
<% n,res = s:recv() %>
<%=n or "recv error"%>
<hr>
<%=res or "recv error"%>
<% s:close() %>
