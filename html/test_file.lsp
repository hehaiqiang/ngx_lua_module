<%
local nginx = nginx
local file = nginx.file
%>
<html>
<head>
</head>
<body>
<% local f = file.open("c:/test.txt") %>
<% local n,res = f:read() %>
n: <%=n%>
<br/>
res: <%=res%>
<hr>
<% local n,err = f:write("kdkdksldskdlsdkkkkkkkkkkkkkkkkkkkkkkkkkk") %>
n: <%=n%>
<br/>
err: <%=err or ""%>
<hr>
<% f:close() %>
</body>
</html>
