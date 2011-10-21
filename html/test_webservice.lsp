<%
local print = print
local nginx = nginx
local req = nginx.http_srv.request
local ws = nginx.webservice

local soap, errstr = ws.serialize({
  body = {
    getSupportCity = {
      uri = 'http://WebXml.com.cn/',
      children = {
        byProvinceName = { text = '广东' },
      }
    },
  }
})

if not soap then print(errstr) return end
print(soap, '<hr>')

local res, errstr = nginx.utils.http({
  method = "POST",
  url = "www.webxml.com.cn/WebServices/WeatherWebService.asmx",
  headers = {
    content_type = "text/xml; charset=utf-8",
    connection = "Keep-Alive",
    accept_language = "zh-cn",
    accept = "*/*",
    user_agent = "Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)"
  },
  body = soap
})

if not res then print(errstr) return end

print('<hr>', res.status, '<hr>')
--print('<hr>', res.body, '<hr>')

local res = ws.parse(res.body)
print('', res.prefix, '<br>')
print('', res.uri, '<hr>')

local header = res.header
if header then
  -- TODO
end

local body = res.body
if body then
  local getSupportCityResponse = body.getSupportCityResponse
  print('', getSupportCityResponse.prefix, '<br>')
  print('', getSupportCityResponse.uri, '<hr>')

  local getSupportCityResult = getSupportCityResponse.children.getSupportCityResult
  print('', getSupportCityResult.prefix, '<br>')
  print('', getSupportCityResult.uri, '<hr>')

  for i, v in ipairs(getSupportCityResult.children) do
    print(v.text, '<br>')
  end
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
