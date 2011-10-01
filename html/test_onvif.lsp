<%
local print = print
local nginx = nginx
local req = nginx.request
local resp = nginx.response
local ws = nginx.webservice

function call(body)
  print(body, '<hr>')

  return nginx.http({
    method = "POST",
    url = "192.168.1.200:80/onvif/services",
    headers = {
      content_type = "text/xml; charset=utf-8",
      connection = "Keep-Alive",
      accept_language = "zh-cn",
      accept = "*/*",
      user_agent = "Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)"
    },
    body = body
  })
end

function get_hostname()
  local soap, errstr = ws.serialize({
    body = {
      GetHostname = {
        uri = "http://www.onvif.org/ver10/device/wsdl",
        prefix = "tds"
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end

  local result, errstr = call(soap)
  if not result then print(errstr, '<hr>') return end
  if result.status ~= resp.OK then return end

  --print(result.body)

  local result, errstr = ws.parse(result.body)
  if not result then print(errstr, '<hr>') return end

  local GetHostnameResponse = result.body.GetHostnameResponse
  local HostnameInformation = GetHostnameResponse.children.HostnameInformation

  local FromDHCP = HostnameInformation.children.FromDHCP
  print('FromDHCP: ', FromDHCP.text, '<br/>')

  local Name = HostnameInformation.children.Name
  print('Name: ', Name.text)
end

function get_capabilites()
  local soap, errstr = ws.serialize({
    body = {
      GetCapabilities = {
        uri = "http://www.onvif.org/ver10/device/wsdl",
        prefix = "tds",
        children = {
          --Category = { prefix = 'tds', text = 'Media' }
        }
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end

  local result, errstr = call(soap)
  if not result then print(errstr, '<hr>') return end
  if result.status ~= resp.OK then return end

  --print(result.body)

  local result, errstr = ws.parse(result.body)
  if not result then print(errstr, '<hr>') return end

  local GetCapabilitiesResponse = result.body.GetCapabilitiesResponse
  local Capabilities = GetCapabilitiesResponse.children.Capabilities

  local Analytics = Capabilities.children.Analytics
  local Device = Capabilities.children.Device
  local Event = Capabilities.children.Event
  local Imaging = Capabilities.children.Imaging

  local Media = Capabilities.children.Media
  local StreamingCapabilities = Media.children.StreamingCapabilities
  local RTPMulticast = StreamingCapabilities.children.RTPMulticast
  print(RTPMulticast.text, '\t')
  local RTP_TCP = StreamingCapabilities.children.RTP_TCP
  print(RTP_TCP.text, '\t')
  local RTP_RTSP_TCP = StreamingCapabilities.children.RTP_RTSP_TCP
  print(RTP_RTSP_TCP.text, '\t')

  local PTZ = Capabilities.children.PTZ
end

function get_configurations()
  local soap, errstr = ws.serialize({
    body = {
      GetConfigurations = {
        uri = "http://www.onvif.org/ver10/ptz/wsdl",
        prefix = "tptz"
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end

  local result, errstr = call(soap)
  if not result then print(errstr, '<hr>') return end
  if result.status ~= resp.OK then return end

  print(result.body)

  local result, errstr = ws.parse(result.body)
  if not result then print(errstr, '<hr>') return end

  local GetConfigurationsResponse = result.body.GetConfigurationsResponse
end

function get_status()
  local soap, errstr = ws.serialize({
    body = {
      GetStatus = {
        uri = "http://www.onvif.org/ver10/ptz/wsdl",
        prefix = "tptz",
        children = {
          ProfileToken = { text = 'mobile_h264' },
        }
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end

  local result, errstr = call(soap)
  if not result then print(errstr, '<hr>') return end
  --if result.status ~= resp.OK then return end

  print(result.body)

  --local result, errstr = ws.parse(result.body)
  --if not result then print(errstr, '<hr>') return end

  --local GetProfilesResponse = result.body.GetProfilesResponse
end

function get_profiles()
  local soap, errstr = ws.serialize({
    body = {
      GetProfiles = {
        uri = "http://www.onvif.org/ver10/media/wsdl",
        prefix = "trt"
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end

  local result, errstr = call(soap)
  if not result then print(errstr, '<hr>') return end
  if result.status ~= resp.OK then return end

  --print(result.body)

  local result, errstr = ws.parse(result.body)
  if not result then print(errstr, '<hr>') return end

  local GetProfilesResponse = result.body.GetProfilesResponse

  for i, Profiles in ipairs(GetProfilesResponse.children) do
    --print(Profiles.attributes.token, '<br/>')

    local Name = Profiles.children.Name
    print('Name: ', Name.text, '<br/>')

    local VideoSourceConfiguration = Profiles.children.VideoSourceConfiguration
    local Name = VideoSourceConfiguration.children.Name
    print(Name.text, '\t')
    local UseCount = VideoSourceConfiguration.children.UseCount
    print(UseCount.text, '\t')
    local SourceToken = VideoSourceConfiguration.children.SourceToken
    print(SourceToken.text, '\t')
    local Bounds = VideoSourceConfiguration.children.Bounds
    local attrs = Bounds.attributes
    print(attrs.height, '\t', attrs.width, '\t', attrs.y, '\t', attrs.x)
    print('<br/>')

    local VideoEncoderConfiguration = Profiles.children.VideoEncoderConfiguration
    --print(VideoEncoderConfiguration.attributes.token, '\t')
    local Name = VideoEncoderConfiguration.children.Name
    --print(Name.text, '\t')
    local UseCount = VideoEncoderConfiguration.children.UseCount
    print(UseCount.text, '\t')
    local Encoding = VideoEncoderConfiguration.children.Encoding
    print(Encoding.text, '\t')

    local Resolution = VideoEncoderConfiguration.children.Resolution
    local Width = Resolution.children.Width
    print('Width:', Width.text, '\t')
    local Height = Resolution.children.Height
    print('Height:', Height.text, '\t')

    local Quality = VideoEncoderConfiguration.children.Quality
    print(Quality.text, '\t')
    local RateControl = VideoEncoderConfiguration.children.RateControl
    local H264 = VideoEncoderConfiguration.children.H264
    local Multicast = VideoEncoderConfiguration.children.Multicast
    local SessionTimeout = VideoEncoderConfiguration.children.SessionTimeout
    print(SessionTimeout.text, '\t')
  end
end

function get_snapshot_uri()
  local soap, errstr = ws.serialize({
    body = {
      GetSnapshotUri = {
        uri = "http://www.onvif.org/ver10/media/wsdl",
        children = {
          ProfileToken = { text = 'mobile_h264' },
        }
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end

  local result, errstr = call(soap)
  if not result then print(errstr, '<hr>') return end
  --if result.status ~= resp.OK then return end

  --print(result.body)

  local result, errstr = ws.parse(result.body)
  if not result then print(errstr, '<hr>') return end

  local GetSnapshotUriResponse = result.body.GetSnapshotUriResponse
  local MediaUri = GetSnapshotUriResponse.children.MediaUri
  local Uri = MediaUri.children.Uri
  print(Uri.text, '<br/>')
end

function get_stream_uri()
  local soap, errstr = ws.serialize({
    body = {
      GetStreamUri = {
        uri = "http://www.onvif.org/ver10/media/wsdl",
        children = {
          StreamSetup = {
            children = {
              Transport = {
                uri = "http://www.onvif.org/ver10/schema",
                children = { Protocol = { text = 'TCP' } },
              },
              Stream = {
                uri = "http://www.onvif.org/ver10/schema",
                text = 'RTP-Unicast' },
            }
          },
          ProfileToken = { text = 'mobile_h264' }
        }
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end

  local result, errstr = call(soap)
  if not result then print(errstr, '<hr>') return end
  if result.status ~= resp.OK then return end

  print(result.body)

  local result, errstr = ws.parse(result.body)
  if not result then print(errstr, '<hr>') return end

  local GetStreamUriResponse = result.body.GetStreamUriResponse
  local MediaUri = GetStreamUriResponse.children.MediaUri
  local Uri = MediaUri.children.Uri
  print(Uri.text)
end

function system_reboot()
  local soap, errstr = ws.serialize({
    body = {
      SystemReboot = {
        uri = "http://www.onvif.org/ver10/device/wsdl",
        prefix = "tds"
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end

  local result, errstr = call(soap)
  if not result then print(errstr, '<hr>') return end
  if result.status ~= resp.OK then return end

  --print(result.body)

  local result, errstr = ws.parse(result.body)
  if not result then print(errstr, '<hr>') return end

  local SystemRebootResponse = result.body.SystemRebootResponse

  local Message = SystemRebootResponse.children.Message
  print('Message: ', Message.text, '<br/>')
end

--get_hostname()
--print('<hr>')

--get_capabilites()
--print('<hr>')

--get_configurations()
--print('<hr>')

get_status()
print('<hr>')

--get_profiles()
--print('<hr>')

--get_snapshot_uri()
--print('<hr>')

--get_stream_uri()
--print('<hr>')

--system_reboot()
%>
<html>
<head>
</head>
<body>
<hr>
request time: <%=req.request_time%>ms
</body>
</html>
