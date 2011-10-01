<%
local print = print
local nginx = nginx
local req = nginx.request
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
  local res, errstr = db.execute(name, 'show databases')

  if not res then print(errstr) return end

  print('col_count:' .. res.col_count .. '<hr>')
  print('row_count:' .. res.row_count .. '<hr>')
  print('affected_rows:' .. res.affected_rows .. '<hr>')
  print('insert_id:' .. res.insert_id .. '<hr>')

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
