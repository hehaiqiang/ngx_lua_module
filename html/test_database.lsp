<%
local print = print
local nginx = nginx
local req = nginx.request
local db = nginx.database

local res = db.execute({
  driver = "libdrizzle",
  host = "127.0.0.1",
  port = 3306,
  user = "root",
  password = "123456",
  database = "mysql",
  sql = "show databases"
})
%>
<html>
<head>
</head>
<body>
err: <%=res.err%>
<br/>
errstr: <%=res.errstr%>
<br/>
col_count: <%=res.col_count or ""%>
<br/>
row_count: <%=res.row_count or ""%>
<br/>
affected_rows: <%=res.affected_rows or ""%>
<br/>
insert_id: <%=res.insert_id or ""%>
<br/>
<% if res.err ~= 0 then print("error") return end %>
<hr>
<table border="1">
<tr>
  <% for i=1,#res.columns do %>
  <td><b><%=res.columns[i]%></b></td>
  <% end %>
</tr>
<% for r=1,#res.rows do %>
<tr>
  <% for i=1,#res.rows[r] do %>
  <td><%=res.rows[r][i]%></td>
  <% end %>
</tr>
<% end %>
</table>
<hr>
request_time: <%=req.request_time%>ms
</body>
</html>
