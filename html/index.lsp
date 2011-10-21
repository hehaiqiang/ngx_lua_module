<%
local req = nginx.http_srv.request

if req.method == req.GET then
  name = req.get['name']
  name = req.get.name
  name = req['name']
  name = req.name
else
  name = req.post['name']
  name = req.post.name
  name = req['name']
  name = req.name
end

name = name or 'world'
%>
<html>
<head>
</head>
<body>
hello, <%=name%>!
<hr>
<form action="index.lsp" method="post">
<input type="text" name="name"/>
<input type="submit" value="submit"/>
</form>
<hr>
request time: <%=req.request_time%>ms
</body>
</html>
