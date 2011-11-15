local string = string
local nginx = nginx
local log = nginx.logger
local udp_srv = nginx.udp_srv
local req = udp_srv.request
local dbd = nginx.database

function use_sqlite3(name)
  local rc, errstr = dbd.create_pool({
    name = name,
    driver = 'sqlite3',
    database = 'conf/log_db.data',
    max_connections = 50
  })
  if not rc then return rc, errstr end

  --[[
  local sql = 'create table logs('
    .. 'id integer primary key autoincrement, '
    .. 'remote_addr text, '
    .. 'remote_user text, '
    .. 'time_local text, '
    .. 'request text, '
    .. 'status text, '
    .. 'body_bytes_sent text, '
    .. 'http_referer text, '
    .. 'http_user_agent text)'
  local res, errstr = dbd.execute(name, sql)
  if not res then return res, errstr end
  --]]

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
  if not rc then return rc, errstr end

  ----[[
  local sql = 'create database ' .. name
  local res, errstr = dbd.execute(name, sql)
  if not res then return res, errstr end
  ----]]

  --[[
  local sql = 'create table logs('
    .. 'id integer primary key auto_increment, '
    .. 'remote_addr text, '
    .. 'remote_user text, '
    .. 'time_local text, '
    .. 'request text, '
    .. 'status text, '
    .. 'body_bytes_sent text, '
    .. 'http_referer text, '
    .. 'http_user_agent text)'
  local res, errstr = dbd.execute(name, sql)
  if not res then return res, errstr end
  --]]

  return true
end

local func = loadstring('return ' .. req.data)
local t = func()
if t.remote_user == '' then t.remote_user = '-' end
if t.http_referer == '' then t.http_referer = '-' end

local sql = 'insert into logs(remote_addr, remote_user, time_local, '
  .. 'request, status, body_bytes_sent, http_referer, http_user_agent) '
  .. 'values("%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s")'
sql = string.format(sql, t.remote_addr, t.remote_user, t.time_local,
  t.request, t.status, t.body_bytes_sent, t.http_referer, t.http_user_agent)

local name = 'log_db'
--local rc, errstr = use_sqlite3(name)
local rc, errstr = use_mysql(name)
if not rc then log.error(log.ALERT, errstr) return end

local res, errstr = dbd.execute(name, sql)
if not res then log.error(log.ALERT, errstr) return end
