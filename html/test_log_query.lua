local print = print
local nginx = nginx
local http_srv = nginx.http_srv;
local req = http_srv.request
local dbd = nginx.database

function use_sqlite3(name)
  local rc, errstr = dbd.create_pool({
    name = name,
    driver = 'sqlite3',
    database = 'conf/log_db.data',
    max_connections = 50
  })
  if not rc then return rc, errstr end

  return true
end

function use_mysql(name)
  local rc, errstr = dbd.create_pool({
    name = name,
    driver = 'libdrizzle',
    host = '127.0.0.1',
    port = 3306,
    user = 'root',
    password = '123456',
    database = 'mysql',
    max_connections = 50
  })
  if not rc then print(errstr) return end
  return true
end

function output(res)
  print('<table border="1">')

  print('<tr>')
  for i = 1, #res.columns do
    print('<td><b>', res.columns[i], '</b></td>')
  end
  print('</tr>')

  for r = 1, #res.rows do
    print('<tr>')
    for c = 1, #res.rows[r] do
      print('<td>', res.rows[r][c], '</td>')
    end
    print('</tr>')
  end

  print('</table>')
end

local name = 'log_db'

--local rc, errstr = use_sqlite3(name)
local rc, errstr = use_mysql(name)
if not rc then print(errstr) return end

local sql = 'select * from ' .. name .. '.logs'
local res, errstr = dbd.execute(name, sql)
if not res then print(errstr) return end

output(res)
