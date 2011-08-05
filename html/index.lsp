<%
local req = nginx.request

--local name = req["name"]
--local name = req.name

if req.method == req.GET then
  name = req.get["name"]
  name = req.get.name
else
  name = req.post["name"]
  name = req.post.name
end

name = name or "world"
%>
<html>
<head><title>hello, <%=name%>!</title></head>
<body>
hello, <%=name%>!
<hr>
<form action="index.lsp" method="post">
<input type="text" name="name"/>
<input type="submit" value="submit"/>
</form>
</body>
</html>