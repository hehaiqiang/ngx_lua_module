local loadstring = loadstring
local nginx = nginx
local log = nginx.logger
local udp_srv = nginx.udp_srv
local req = udp_srv.request
--local db = require('sqlite3_log_db')
local db = require('mysql_log_db')

local func = loadstring('return ' .. req.data)
local t = func()
if t.remote_user == '' then t.remote_user = '-' end
if t.http_referer == '' then t.http_referer = '-' end

--[[
local rc, errstr = db.create_db_pool()
if not rc then log.error(log.ALERT, errstr) return end

local res, errstr = db.insert_logs(t.remote_addr, t.remote_user, t.time_local,
  t.request, t.status, t.body_bytes_sent, t.http_referer, t.http_user_agent)
if not res then log.error(log.ALERT, errstr) return end
--]]
