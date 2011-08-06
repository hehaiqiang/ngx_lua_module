<%
local print = print
local nginx = nginx
local log = nginx.logger
%>
<html>
<head>
</head>
<body>
<%
-- writing some messages into the log file of the nginx
log.error(log.ALERT, "test alert" .. 1 .. 10)
log.debug(log.DEBUG_HTTP, "test debug http")
log.error(log.ERR, "test error")
log.error(log.EMERG, 1000)
%>
please opening the log file of the nginx to view messages.
</body>
</html>
