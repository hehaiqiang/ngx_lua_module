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
log.error(log.ALERT, "test alert" .. 1 .. 10)
log.debug(log.DEBUG_HTTP, "test debug http")
log.error(log.ERR, "test error")
log.error(log.EMERG, 1000)
%>
open error.log to view messages.
</body>
</html>
