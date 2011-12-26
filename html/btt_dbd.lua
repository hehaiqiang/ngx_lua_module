local print = print
local nginx = nginx
local btt = nginx.btt
local dbd = nginx.database
local log = nginx.logger
local utils = nginx.utils

utils.sleep('3s')

local rc, err = dbd.create_pool({
  name = 'btt',
  driver = 'libdrizzle',
  host = '127.0.0.1',
  port = 3306,
  database = 'btt',
  user = 'btt',
  password = '123456',
  max_connections = 50
})

while true do
  local to_db_peers = btt.to_db_peers(3, 1)

  if to_db_peers then
    for i,v in ipairs(to_db_peers) do
      local sql = string.format(
        "insert into btt_peers(info_hash_hex, peer_id_hex, "
        .. "internal_ip, internal_ip_str, internal_port, "
        .. "external_ip, external_ip_str, external_port, "
        .. "downloaded, uploaded, `left`) "
        .. "values('%s', '%s', %d, '%s', %d, %d, '%s', %d, %d, %d, %d)",
        v.info_hash_hex,
        v.peer_id_hex,
        v.internal_ip,
        v.internal_ip_str,
        v.internal_port,
        v.external_ip,
        v.external_ip_str,
        v.external_port,
        v.downloaded,
        v.uploaded,
        v.left)
      local rc, err = dbd.execute('btt', sql)
    end
  else
    log.error(log.ALERT, 'btt.to_db_peers() failed')
  end

  utils.sleep('5s')
end
