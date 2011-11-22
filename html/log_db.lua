module(..., package.seeall)

local print = print
local nginx = nginx
local dbd = nginx.database

db_name = 'log_db'
tbl_name = 'logs'

function destroy_db_pool()
  dbd.destroy_pool(db_name)
end

function output(res)
  print('col_count:' .. res.col_count .. '<hr>')
  print('row_count:' .. res.row_count .. '<hr>')
  print('affected_rows:' .. res.affected_rows .. '<hr>')
  print('insert_id:' .. res.insert_id .. '<hr>')

  if not res.columns then return end

  print('<table border="1">')
  print('<tr>')
  for i = 1, #res.columns do
    print('<td><b>' .. res.columns[i] .. '</b></td>')
  end
  print('</tr>')
  for r = 1, #res.rows do
    print('<tr>')
    for c = 1, #res.rows[r] do
      print('<td>' .. res.rows[r][c] .. '</td>')
    end
    print('</tr>')
  end
  print('</table>')
end
