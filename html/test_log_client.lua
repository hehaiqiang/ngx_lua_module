local nginx = nginx
local log = nginx.logger
local socket = nginx.socket
local http_srv = nginx.http_srv
local var = http_srv.variable

local s, errstr = socket.open('127.0.0.1:8080', socket.UDP)
if not s then log.error(log.ALERT, errstr) return end

local remote_user = var.remote_user or ''
local http_referer = var.http_referer or ''

local str = '{'
  .. 'remote_addr="' .. var.remote_addr .. '",'
  .. 'remote_user="' .. remote_user .. '",'
  .. 'time_local="' .. var.time_local .. '",'
  .. 'request="' .. var.request .. '",'
  .. 'status="' .. var.status .. '",'
  .. 'body_bytes_sent="' .. var.body_bytes_sent .. '",'
  .. 'http_referer="' .. http_referer .. '",'
  .. 'http_user_agent="' .. var.http_user_agent .. '",'
  .. '}'

s:send(str)
s:close()
