local print = print
--local db = require('sqlite3_log_db')
local db = require('mysql_log_db')

local rc, errstr = db.create_db_pool()
if not rc then print(errstr) return end

local res, errstr = db.query_logs()
if not res then print(errstr) return end

db.output(res)
