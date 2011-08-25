<%
local print = print
local nginx = nginx

local rc,err = nginx.smtp({
  host = "smtp.126.com",
  user = "ngxteam@126.com",
  password = "xxxxxxxxx",
  from = "ngxteam@126.com",
  to = {
    "ngwsx2008@126.com",
    "hqhe1982@126.com",
    "184815157@qq.com",
    "hqhe1982@hotmail.com"
  },
  subject = "ngx_lua_module",
  content = "ngx_lua_module test smtp"
})

print(rc or "rc is null")

if rc ~= nginx.OK then
  print("<hr>")
  print(err or "err is null")
end
%>
