<%
local print = print
local string = string
local nginx = nginx
local file = nginx.file
local req = nginx.request
local socket = nginx.socket

function ptz()
  --local direction = 'left'
  --local direction = 'right'
  --local direction = 'up'
  --local direction = 'down'
  --local direction = 'up-left'
  --local direction = 'up-right'
  --local direction = 'down-left'
  --local direction = 'down-right'
  --local body = string.format('Move=%s,12', direction)

  --local zoom = 'tele'
  --local zoom = 'wide'
  --local body = string.format('Move=%s,8', zoom)

  --local focus = 'near'
  --local focus = 'far'
  --local focus = 'onepushaf'
  --local body = string.format('Move=%s,6', focus)

  --local body = 'AreaZoom=1,1,10,10'
  --local body = 'AbsoluteZoom=100'
  --local body = 'AbsolutePanTilt=300,300,12'

  --local cgi = 'ptzf.cgi'

  local body = 'HomePos=ptz-recall'
  local cgi = 'presetposition.cgi'

  local res, errstr = nginx.http({
    method = 'POST',
    url = '192.168.1.188/command/' .. cgi,
    headers = {
      connection = 'close',
      authorization = 'Basic ' .. nginx.encode_base64('admin:admin'),
    },
    body = body
  })

  if not res then print(errstr) return end

  print('<hr>', res.status, '<hr>')
  --print('<hr>', res.body, '<hr>')

  print('<table border="1">')
  for k,v in pairs(res.headers) do
    print('<tr><td>', k, '</td><td>', v, '</td></tr>')
  end
  print('</table>')
end

function ptz_stop()
  --local body = 'Cancel=on'

  --local body = 'Move=stop,pantilt'
  local body = 'Move=stop,motor'

  --local body = 'Move=stop,zoom'
  --local body = 'Move=stop,focus'

  local res, errstr = nginx.http({
    method = 'POST',
    url = '192.168.1.188/command/ptzf.cgi',
    headers = {
      connection = 'close',
      authorization = 'Basic ' .. nginx.encode_base64('admin:admin'),
    },
    body = body
  })

  if not res then print(errstr) return end

  print('<hr>', res.status, '<hr>')
  --print('<hr>', res.body, '<hr>')

  print('<table border="1">')
  for k,v in pairs(res.headers) do
    print('<tr><td>', k, '</td><td>', v, '</td></tr>')
  end
  print('</table>')
end

function system_reboot()
  local res, errstr = nginx.http({
    url = '192.168.1.188/command/main.cgi?System=reboot',
    headers = {
      connection = 'close',
      authorization = 'Basic ' .. nginx.encode_base64('admin:admin'),
    },
  })

  if not res then print(errstr) return end

  print('<hr>', res.status, '<hr>')
  print('<hr>', res.body, '<hr>')

  print('<table border="1">')
  for k,v in pairs(res.headers) do
    print('<tr><td>', k, '</td><td>', v, '</td></tr>')
  end
  print('</table>')
end

function snapshot()
  local res, errstr = nginx.http({
    url = '192.168.1.188/jpeg/vga.jpg'
  })

  if not res then print(errstr) return end

  print('<hr>', res.status, '<hr>')
  --print('<hr>', res.body, '<hr>')

  print('<table border="1">')
  for k,v in pairs(res.headers) do
    print('<tr><td>', k, '</td><td>', v, '</td></tr>')
  end
  print('</table>')

  local f = file.open('c:/temp/snapshot.jpg', file.WRONLY, file.TRUNCATE, file.DEFAULT_ACCESS)
  f:write(res.body)
  f:close()
end

function speak()
  local host = '192.168.1.188'
  local s, errstr = socket.open(host)
  if not s then print(errstr) return end

  -- TODO: format

  local n, errstr = s:send(
    'GET /audio-out/ HTTP/1.1\r\n'
    .. 'Host: ' .. host .. '\r\n'
    .. 'Connection: close\r\n'
    .. '\r\n')
  if not n then print(errstr) s:close() return end

  --local f = file.open('c:/temp/audio.g711', file.WRONLY, file.TRUNCATE, file.DEFAULT_ACCESS)
  --for i = 1,999 do
  --  local data, errstr = s:recv()
  --  if not data then print('<hr>', errstr) s:close() return end
  --  f:write(data)
  --end
  --f:close()

  s:close()
end

function audio()
  local host = '192.168.1.188'
  local s, errstr = socket.open(host)
  if not s then print(errstr) return end

  local n, errstr = s:send(
    'GET /audio HTTP/1.1\r\n'
    .. 'Host: ' .. host .. '\r\n'
    .. 'Connection: Keep-Alive\r\n'
    .. '\r\n')
  if not n then print(errstr) s:close() return end

  local f = file.open('c:/temp/audio.g711', file.WRONLY, file.TRUNCATE, file.DEFAULT_ACCESS)
  for i = 1,999 do
    local data, errstr = s:recv()
    if not data then print('<hr>', errstr) s:close() return end
    f:write(data)
  end
  f:close()

  s:close()
end

function video()
  local host = '192.168.1.188'
  local s, errstr = socket.open(host)
  if not s then print(errstr) return end

  --local uri = '/image'
  --local uri = '/mjpeg'
  local uri = '/mpeg4'
  --local uri = '/h264'
  local n, errstr = s:send(
    'GET ' .. uri .. ' HTTP/1.1\r\n'
    .. 'Host: ' .. host .. '\r\n'
    .. 'Connection: Keep-Alive\r\n'
    .. '\r\n')
  if not n then print(errstr) s:close() return end

  local f = file.open('c:/temp/video.m4e', file.WRONLY, file.TRUNCATE, file.DEFAULT_ACCESS)
  for i = 1,999 do
    local data, errstr = s:recv()
    if not data then print('<hr>', errstr) s:close() return end
    f:write(data)
  end
  f:close()

  s:close()
end

--ptz()
--ptz_stop()
--system_reboot()
--snapshot()
--speak()
--audio()
--video()
%>
<html>
<head>
</head>
<body>
<hr>
request time: <%=req.request_time%>ms
</body>
</html>
