<%
local print = print
local nginx = nginx
local req = nginx.http_srv.request
local socket = nginx.socket

function test_tcp()
  local s, errstr = socket.open('127.0.0.1:8284', socket.TCP)
  if not s then print(errstr) return end

  -- login

  local rc, errstr = s:send('login')
  if not rc then print(errstr) s:close() return end

  local res, errstr = s:recv()
  if not res then print(errstr) s:close() return end
  print(res)

  -- logout

  local rc, errstr = s:send('logout')
  if not rc then print(errstr) s:close() return end

  local res, errstr = s:recv()
  if not res then print(errstr) s:close() return end
  print(res)

  s:close()
end

function test_udp()
  local s, errstr = socket.open('127.0.0.1:8284', socket.UDP)
  if not s then print(errstr) return end

  -- login

  local rc, errstr = s:send('login')
  if not rc then print(errstr) s:close() return end

  local res, errstr = s:recv()
  if not res then print(errstr) s:close() return end
  print(res)

  -- logout

  local rc, errstr = s:send('logout')
  if not rc then print(errstr) s:close() return end

  local res, errstr = s:recv()
  if not res then print(errstr) s:close() return end
  print(res)

  s:close()
end

if req['type'] == 'udp' then
  test_udp()
else
  test_tcp()
end
%>
<html>
<head>
</head>
<body>
<hr>
request time: <%=req.request_time%>ms
</body>
</html>
