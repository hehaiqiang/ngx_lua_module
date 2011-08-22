<%
local nginx = nginx
local resp = nginx.response
local socket = nginx.socket
resp.content_type = "text/html"
%>
<% local s = socket.open("smtp.126.com:25") %>
<%

local n,res = s:recv()
print(n .. "<br>" .. res .. "<hr>")

-- hello
local n = s:send("EHLO ngxteam@126.com\r\n")
print(n .. "<br/>")
local n,res = s:recv()
print(n .. "<br>" .. res .. "<hr>")

-- login
local n = s:send("AUTH LOGIN\r\n")
print(n .. "<br/>")
local n,res = s:recv()
print(n .. "<br>" .. res .. "<hr>")

-- user
local n = s:send(nginx.encode_base64("ngxteam") .. "\r\n")
print(n .. "<br/>")
local n,res = s:recv()
print(n .. "<br>" .. res .. "<hr>")

-- password
local n = s:send(nginx.encode_base64("xxxxxxxx") .. "\r\n")
print(n .. "<br/>")
local n,res = s:recv()
print(n .. "<br>" .. res .. "<hr>")

-- sender
local n = s:send("MAIL FROM:<ngxteam@126.com>\r\n")
print(n .. "<br/>")
local n,res = s:recv()
print(n .. "<br>" .. res .. "<hr>")

-- receiver
local n = s:send("RCPT TO:<ngwsx2008@126.com>\r\n")
print(n .. "<br/>")
local n,res = s:recv()
print(n .. "<br>" .. res .. "<hr>")

-- receiver
local n = s:send("RCPT TO:<184815157@qq.com>\r\n")
print(n .. "<br/>")
local n,res = s:recv()
print(n .. "<br>" .. res .. "<hr>")

-- mail
local n = s:send("DATA\r\n")
print(n .. "<br/>")
local n,res = s:recv()
print(n .. "<br>" .. res .. "<hr>")

-- mail content
local n = s:send("Subject: test title\r\nTo: 184815157@qq.com\r\nTo: ngwsx2008@126.com\r\n\r\ntest body\r.\n")
print(n .. "<br/>")
local n,res = s:recv()
print(n .. "<br>" .. res .. "<hr>")

-- quit
local n = s:send("QUIT\r\n")
print(n .. "<br/>")
local n,res = s:recv()
print(n .. "<br>" .. res .. "<hr>")

%>
