local nginx = nginx
local log = nginx.logger
local udt_srv = nginx.udt_srv
local req = udt_srv.request
local resp = udt_srv.response

log.error(log.ALERT, 'test udt server')

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
