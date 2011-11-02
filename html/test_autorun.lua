local nginx = nginx
local log = nginx.logger
local utils = nginx.utils

for i = 1,150 do
  log.error(log.ALERT, i)
  utils.sleep('10s')
end
