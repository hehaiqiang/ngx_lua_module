<%
local print = print
local nginx = nginx
local http_srv = nginx.http_srv
local req = http_srv.request
local resp = http_srv.response
local ws = nginx.webservice

function Call(body)
  print('\r\n\r\n\r\n\r\n', body, '\r\n')

  local result, errstr = nginx.utils.http({
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

  print(result.body, '<hr>')

  return result, errstr
end

function GetHostname()
  local soap, errstr = ws.serialize({
    body = {
      GetHostname = {
        uri = "http://www.onvif.org/ver10/device/wsdl",
        prefix = "tds"
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end
  local result, errstr = Call(soap)
end

function GetCapabilites()
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
  local result, errstr = Call(soap)
end

function GetConfigurations()
  local soap, errstr = ws.serialize({
    body = {
      GetConfigurations = {
        uri = "http://www.onvif.org/ver10/ptz/wsdl",
        prefix = "tptz"
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end
  local result, errstr = Call(soap)
end

function GetStatus()
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
  local result, errstr = Call(soap)
end

function GetProfiles()
  local soap, errstr = ws.serialize({
    body = {
      GetProfiles = {
        uri = "http://www.onvif.org/ver10/media/wsdl",
        prefix = "trt"
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end
  local result, errstr = Call(soap)
end

function GetVideoSources()
  local soap, errstr = ws.serialize({
    body = {
      GetVideoSources = {
        uri = "http://www.onvif.org/ver10/media/wsdl",
        prefix = "trt"
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end
  local result, errstr = Call(soap)
end

function GetVideoSourceConfigurations()
  local soap, errstr = ws.serialize({
    body = {
      GetVideoSourceConfigurations = {
        uri = "http://www.onvif.org/ver10/media/wsdl",
        prefix = "trt"
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end
  local result, errstr = Call(soap)
end

function GetVideoSourceConfiguration()
  local soap, errstr = ws.serialize({
    body = {
      GetVideoSourceConfiguration = {
        uri = "http://www.onvif.org/ver10/media/wsdl",
        prefix = "trt",
        children = {
          ConfigurationToken = { prefix = 'trt', text = '0' },
        }
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end
  local result, errstr = Call(soap)
end

function GetVideoSourceConfigurationOptions()
  local soap, errstr = ws.serialize({
    body = {
      GetVideoSourceConfigurationOptions = {
        uri = "http://www.onvif.org/ver10/media/wsdl",
        prefix = "trt",
        children = {
          --ConfigurationToken = { prefix = 'trt', text = '0' },
          --ProfileToken = { prefix = 'trt', text = 'mobile_h264' },
        }
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end
  local result, errstr = Call(soap)
end

function GetVideoEncoderConfigurations()
  local soap, errstr = ws.serialize({
    body = {
      GetVideoEncoderConfigurations = {
        uri = "http://www.onvif.org/ver10/media/wsdl",
        prefix = "trt"
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end
  local result, errstr = Call(soap)
end

function GetVideoEncoderConfiguration()
  local soap, errstr = ws.serialize({
    body = {
      GetVideoEncoderConfiguration = {
        uri = "http://www.onvif.org/ver10/media/wsdl",
        prefix = "trt",
        children = {
          ConfigurationToken = { prefix = 'trt', text = '0' },
        }
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end
  local result, errstr = Call(soap)
end

function GetVideoEncoderConfigurationOptions()
  local soap, errstr = ws.serialize({
    body = {
      GetVideoEncoderConfigurationOptions = {
        uri = "http://www.onvif.org/ver10/media/wsdl",
        prefix = "trt",
        children = {
          --ConfigurationToken = { prefix = 'trt', text = '0' },
          --ProfileToken = { prefix = 'trt', text = 'mobile_h264' },
        }
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end
  local result, errstr = Call(soap)
end

function GetAudioSources()
  local soap, errstr = ws.serialize({
    body = {
      GetAudioSources = {
        uri = "http://www.onvif.org/ver10/media/wsdl",
        prefix = "trt"
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end
  local result, errstr = Call(soap)
end

function GetAudioSourceConfigurations()
  local soap, errstr = ws.serialize({
    body = {
      GetAudioSourceConfigurations = {
        uri = "http://www.onvif.org/ver10/media/wsdl",
        prefix = "trt"
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end
  local result, errstr = Call(soap)
end

function GetAudioSourceConfiguration()
  local soap, errstr = ws.serialize({
    body = {
      GetAudioSourceConfiguration = {
        uri = "http://www.onvif.org/ver10/media/wsdl",
        prefix = "trt",
        children = {
          ConfigurationToken = { prefix = 'trt', text = '0' },
        }
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end
  local result, errstr = Call(soap)
end

function GetAudioSourceConfigurationOptions()
  local soap, errstr = ws.serialize({
    body = {
      GetAudioSourceConfigurationOptions = {
        uri = "http://www.onvif.org/ver10/media/wsdl",
        prefix = "trt",
        children = {
          --ConfigurationToken = { prefix = 'trt', text = '0' },
          --ProfileToken = { prefix = 'trt', text = 'mobile_h264' },
        }
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end
  local result, errstr = Call(soap)
end

function GetAudioEncoderConfigurations()
  local soap, errstr = ws.serialize({
    body = {
      GetAudioEncoderConfigurations = {
        uri = "http://www.onvif.org/ver10/media/wsdl",
        prefix = "trt"
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end
  local result, errstr = Call(soap)
end

function GetAudioEncoderConfiguration()
  local soap, errstr = ws.serialize({
    body = {
      GetAudioEncoderConfiguration = {
        uri = "http://www.onvif.org/ver10/media/wsdl",
        prefix = "trt",
        children = {
          ConfigurationToken = { prefix = 'trt', text = '0' },
        }
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end
  local result, errstr = Call(soap)
end

function GetAudioEncoderConfigurationOptions()
  local soap, errstr = ws.serialize({
    body = {
      GetAudioEncoderConfigurationOptions = {
        uri = "http://www.onvif.org/ver10/media/wsdl",
        prefix = "trt",
        children = {
          --ConfigurationToken = { prefix = 'trt', text = '0' },
          --ProfileToken = { prefix = 'trt', text = 'mobile_h264' },
        }
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end
  local result, errstr = Call(soap)
end

function GetSnapshotUri()
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
  local result, errstr = Call(soap)
end

function GetStreamUri()
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
  local result, errstr = Call(soap)
end

function SystemReboot()
  local soap, errstr = ws.serialize({
    body = {
      SystemReboot = {
        uri = "http://www.onvif.org/ver10/device/wsdl",
        prefix = "tds"
      }
    }
  })
  if not soap then print(errstr, '<hr>') return end
  local result, errstr = Call(soap)
end

--GetHostname()
--GetCapabilites()
--GetConfigurations()
--GetStatus()
--GetProfiles()

GetVideoSources()
--GetVideoSourceConfigurations()
--GetVideoSourceConfiguration()
--GetVideoSourceConfigurationOptions()
--GetVideoEncoderConfigurations()
--GetVideoEncoderConfiguration()
--GetVideoEncoderConfigurationOptions()

GetAudioSources()
--GetAudioSourceConfigurations()
--GetAudioSourceConfiguration()
--GetAudioSourceConfigurationOptions()
--GetAudioEncoderConfigurations()
--GetAudioEncoderConfiguration()
--GetAudioEncoderConfigurationOptions()

--GetSnapshotUri()
--GetStreamUri()
--SystemReboot()
%>
<html>
<head>
</head>
<body>
<hr>
request time: <%=req.request_time%>ms
</body>
</html>
