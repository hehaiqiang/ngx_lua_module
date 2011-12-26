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

function test_udt()
  local start_time = req.request_time

  local s, errstr = socket.open('127.0.0.1:9000', socket.UDT)
  if not s then print(errstr) return end

  local end_time = req.request_time
  print('connect time: ' .. end_time - start_time .. 'ms<br/>')

  -- login

  start_time = req.request_time

  local rc, errstr = s:send('login')
  if not rc then print(errstr) s:close() return end

  end_time = req.request_time
  print('send time: ' .. end_time - start_time .. 'ms<br/>')

  start_time = req.request_time

  local res, errstr = s:recv()
  if not res then print(errstr) s:close() return end
  print(res .. '<br/>')

  end_time = req.request_time
  print('recv time: ' .. end_time - start_time .. 'ms<br/>')

  -- logout

  start_time = req.request_time

  local rc, errstr = s:send('logout')
  if not rc then print(errstr) s:close() return end

  end_time = req.request_time
  print('send time: ' .. end_time - start_time .. 'ms<br/>')

  start_time = req.request_time

  local res, errstr = s:recv()
  if not res then print(errstr) s:close() return end
  print(res .. '<br/>')

  end_time = req.request_time
  print('recv time: ' .. end_time - start_time .. 'ms<br/>')

  s:close()
end

local type = req['type']

if type == 'udp' then
  test_udp()
elseif type == 'udt' then
  test_udt()
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
