<%
local print = print
local nginx = nginx
local req = nginx.request
local socket = nginx.socket

function test_tcp()
  local s, errstr = socket.open("www.nginx.org:80")
  if not s then print(errstr) return end

  local n, errstr = s:send("GET / HTTP/1.1\r\nHost: www.nginx.org\r\n\r\n")
  if not n then print(errstr) s:close() return end

  for i = 1, 8 do
    local data, errstr = s:recv()
    if not data then print("<hr>" .. errstr) break end
    print(data)
  end

  s:close()
end

function test_udp()
  local s = socket.open("127.0.0.1:53", socket.UDP)
  if not s then print(errstr) return end

  -- TODO: s:send() and s:recv()

  s:close()
end

if req["type"] == "udp" then
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
test socket api
<hr>
request time: <%=req.request_time%>ms
</body>
</html>
