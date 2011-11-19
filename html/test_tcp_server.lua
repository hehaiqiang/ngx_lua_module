local nginx = nginx
local log = nginx.logger
local tcp_srv = nginx.tcp_srv
local req = tcp_srv.request
local resp = tcp_srv.response

log.error(log.ALERT, 'test tcp server')

-- login

local data, errstr = req.recv()
if not data then log.error(log.ALERT, errstr) return end
log.error(log.ALERT, data)

print('ok')

local rc, errstr = resp.send()
if not rc then log.error(log.ALERT, errstr) end

-- logout

local data, errstr = req.recv()
if not data then log.error(log.ALERT, errstr) return end
log.error(log.ALERT, data)

print('ok')

local rc, errstr = resp.send()
if not rc then log.error(log.ALERT, errstr) end
