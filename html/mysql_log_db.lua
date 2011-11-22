module(..., package.seeall)

local setmetatable = setmetatable
local string = string
local nginx = nginx
local dbd = nginx.database

local log_db = require('log_db')
log_db.__index = log_db
setmetatable(_M, log_db)

local tbl_name = log_db.db_name .. '.' .. log_db.tbl_name

function create_db_pool()
  return dbd.create_pool({
    name = log_db.db_name,
    driver = 'libdrizzle',
    host = '127.0.0.1',
    port = 3306,
    database = 'mysql',
    user = 'root',
    password = '123456',
    max_connections = 50
  })
end

function create_logs_db()
  local sql = 'create database ' .. log_db.db_name
  return dbd.execute(log_db.db_name, sql)
end

function drop_logs_db()
  local sql = 'drop database ' .. log_db.db_name
  return dbd.execute(log_db.db_name, sql)
end

function create_logs()
  local sql = 'create table ' .. tbl_name .. '('
    .. 'id integer primary key auto_increment, '
    .. 'remote_addr text, '
    .. 'remote_user text, '
    .. 'time_local text, '
    .. 'request text, '
    .. 'status text, '
    .. 'body_bytes_sent text, '
    .. 'http_referer text, '
    .. 'http_user_agent text)'
  return dbd.execute(log_db.db_name, sql)
end

function drop_logs()
  local sql = 'drop table ' .. tbl_name
  return dbd.execute(log_db.db_name, sql)
end

function insert_logs(remote_addr, remote_user, time_local, request, status,
    body_bytes_sent, http_referer, http_user_agent)
  local sql = 'insert into ' .. tbl_name .. '(remote_addr, remote_user, '
    .. 'time_local, request, status, body_bytes_sent, http_referer, '
    .. 'http_user_agent) '
    .. 'values("%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s")'
  sql = string.format(sql, remote_addr, remote_user, time_local, request,
    status, body_bytes_sent, http_referer, http_user_agent)
  return dbd.execute(log_db.db_name, sql)
end

function query_logs()
  local sql = 'select * from ' .. tbl_name
  return dbd.execute(log_db.db_name, sql)
end
