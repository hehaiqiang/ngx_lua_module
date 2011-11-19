local nginx = nginx
local log = nginx.logger
local udp_srv = nginx.udp_srv
local req = udp_srv.request

log.error(log.ALERT, 'test udp server')

log.error(log.ALERT, req.data)

print('ok')
