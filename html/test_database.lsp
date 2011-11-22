<%
local print = print
local nginx = nginx
local req = nginx.http_srv.request
--local db = require('sqlite3_log_db')
local db = require('mysql_log_db')

local rc, errstr = db.create_db_pool()
if not rc then print(errstr) return end

--local res, errstr = db.create_logs_db()
--local res, errstr = db.drop_logs_db()

--local res, errstr = db.create_logs()
--local res, errstr = db.drop_logs()

local res, errstr = db.query_logs()

if not res then print(errstr) return end

db.output(res)
%>
<html>
<head>
</head>
<body>
<hr>
test database api
<hr>
request time: <%=req.request_time%>ms
</body>
</html>
