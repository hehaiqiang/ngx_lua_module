<%
local print = print
local nginx = nginx
local req = nginx.http_srv.request
local db = nginx.database

function create_db_pool(name)
  local rc, errstr = db.create_pool({
    name = name,
    driver = 'libdrizzle',
    host = '127.0.0.1',
    port = 3306,
    database = 'mysql',
    user = 'root',
    password = '123456',
    max_connections = 50
  })

  --print(tostring(rc));

  if not rc then print(errstr or '') return false end

  return true
end

function test_db(name)
  --local sql = 'show databases'
  --local sql = 'show tables'
  local sql = 'select * from mysql.user'
  --local sql = 'create database log_db'
  --local sql = 'drop database log_db'
  --[[
  local sql = 'create table log_db.logs('
    .. 'id integer primary key auto_increment, '
    .. 'remote_addr text, '
    .. 'remote_user text, '
    .. 'time_local text, '
    .. 'request text, '
    .. 'status text, '
    .. 'body_bytes_sent text, '
    .. 'http_referer text, '
    .. 'http_user_agent text)'
  --]]
  --local sql = 'drop table log_db.logs'
  --local sql = 'select * from log_db.logs'

  local res, errstr = db.execute(name, sql)

  if not res then print(errstr) return end

  print('col_count:' .. res.col_count .. '<hr>')
  print('row_count:' .. res.row_count .. '<hr>')
  print('affected_rows:' .. res.affected_rows .. '<hr>')
  print('insert_id:' .. res.insert_id .. '<hr>')

  if res.col_count == 0 then return end

  print('<table border="1">')
  print('<tr>')
  for i = 1, #res.columns do
    print('<td><b>' .. res.columns[i] .. '</b></td>')
  end
  print('</tr>')
  for r = 1, #res.rows do
    print('<tr>')
    for c = 1, #res.rows[r] do
      print('<td>' .. res.rows[r][c] .. '</td>')
    end
    print('</tr>')
  end
  print('</table>')
end

local name = 'test'
if not create_db_pool(name) then return end
test_db(name)
--db.destroy_pool(name)
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
