<%
local print = print
local nginx = nginx
local btt = nginx.btt
local http_srv = nginx.http_srv
local req = http_srv.request

local torrents = btt.torrents()
if not torrents then print('btt.torrents() failed') return end

local info_hash = req['info_hash']
if info_hash then
  peers = btt.peers(info_hash)
  if not peers then print('btt.peers() failed') return end
end

local to_db_peers = btt.to_db_peers()
if not to_db_peers then print('btt.to_db_peers() failed') return end
%>
<html>
<head></head>
<body>
<a href="?">main</a>
<hr>
<!-- torent lis -->
<%=#torrents%> torrents.
<hr>
<table border="1">
  <tr><td>info_hash</td></tr>
  <% for i,v in ipairs(torrents) do %>
  <tr><td><a href="?info_hash=<%=v.info_hash%>"><%=v.info_hash%></a></td></tr>
  <% end %>
</table>

<!-- peer list of the torrent -->
<% if info_hash and peers then %>
<hr>
<%=#peers%> peers.
<hr>
<table border="1">
  <tr>
  <td>info_hash(hex)</td>
  <td>peer_id(hex)</td>
  <td>peer_id</td>
  <td>internal_ip_str</td>
  <td>internal_ip</td>
  <td>internal_port</td>
  <td>external_ip_str</td>
  <td>external_ip</td>
  <td>external_port</td>
  <td>downloaded</td>
  <td>uploaded</td>
  <td>left</td>
  </tr>
  <% for i,v in ipairs(peers) do %>
  <tr>
  <td><%=v.info_hash_hex%></td>
  <td><%=v.peer_id_hex%></td>
  <td><%=v.peer_id%></td>
  <td><%=v.internal_ip_str%></td>
  <td><%=v.internal_ip%></td>
  <td><%=v.internal_port%></td>
  <td><%=v.external_ip_str%></td>
  <td><%=v.external_ip%></td>
  <td><%=v.external_port%></td>
  <td><%=v.downloaded%></td>
  <td><%=v.uploaded%></td>
  <td><%=v.left%></td>
  </tr>
  <% end %>
</table>
<% end %>

<!-- to db peer list -->
<hr>
<%=#to_db_peers%> peers (to db).
<table border="1">
  <tr>
  <td>info_hash(hex)</td>
  <td>peer_id(hex)</td>
  <td>peer_id</td>
  <td>internal_ip_str</td>
  <td>internal_ip</td>
  <td>internal_port</td>
  <td>external_ip_str</td>
  <td>external_ip</td>
  <td>external_port</td>
  <td>downloaded</td>
  <td>uploaded</td>
  <td>left</td>
  </tr>
  <% for i,v in ipairs(to_db_peers) do %>
  <tr>
  <td><%=v.info_hash_hex%></td>
  <td><%=v.peer_id_hex%></td>
  <td><%=v.peer_id%></td>
  <td><%=v.internal_ip_str%></td>
  <td><%=v.internal_ip%></td>
  <td><%=v.internal_port%></td>
  <td><%=v.external_ip_str%></td>
  <td><%=v.external_ip%></td>
  <td><%=v.external_port%></td>
  <td><%=v.downloaded%></td>
  <td><%=v.uploaded%></td>
  <td><%=v.left%></td>
  </tr>
  <% end %>
</table>
</body>
</html>
