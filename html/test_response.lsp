<%
local print = print
local nginx = nginx
local req = nginx.request
local resp = nginx.response
resp.content_type = "text/html"
%>
<html>
<head><title></title></head>
<body>
<%
local one = req["one"] or 1
local two = req.two or 2
local three = req.post["three"] or 3
local four = req.post.four or 4
%>
hello, <%=one%><%=two%><%=three%><%=four%>!
<hr>
<form action="test_response.lsp" method="post">
<input type="text" name="one"/>
<input type="text" name="two"/>
<input type="text" name="three"/>
<input type="text" name="four"/>
<input type="submit" value="submit"/>
</form>
<hr>
</body>
</html>
