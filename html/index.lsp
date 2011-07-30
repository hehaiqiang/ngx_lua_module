<%
-- This is a lua server page

local nginx = nginx
local core = nginx.core
local dbd = nginx.dbd

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
if conn ~= nil then
  if conn:connect("127.0.0.1", 3306, "root", "123456", "mysql") == core.OK then
    if conn:query("show databases") == core.OK then
%>
<tr>
   <% while conn:column_read() == core.OK do %>
<td><%=conn:column_name()%></td>
   <% end %>
</tr>
   <% while conn:row_read() == core.OK do %>
<tr>
<%
        repeat
          local value = conn:field_read()
          if value == core.ERROR or value == core.DONE then break end
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
</body>
</html>
