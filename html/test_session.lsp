<%
local print = print
local nginx = nginx
local session = nginx.session

session.create()
session.set_param("test", 1)
session.get_param("test")
session["test"] = "test"
session["test_int"] = 1
print(session["test"] or "")
print(session["test_int"] or 2)
session["test"] = nil
session["test_int"] = nil
session.destroy()
%>
<html>
<head>
</head>
<body>
</body>
</html>