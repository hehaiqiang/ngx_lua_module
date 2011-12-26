local print = print
local nginx = nginx
local http_srv = nginx.http_srv
local btt = http_srv.btt

if not btt.announce() then
  print('d14:failure reason21:internal server errore')
end
