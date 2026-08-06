local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
AgentTeslaがexfiltration C2として利用するFTP endpointを確認します。既定ではserver bannerだけを
取得します。agenttesla.userとagenttesla.passを明示した場合だけUSER/PASS/QUITを送り、
検体から復元した資格情報が現在も有効かを確認します。directory操作やfile転送は行いません。
]]

author = "AI-security-analysis"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "malware", "discovery"}

portrule = function(_, port)
  return port.protocol == "tcp" and port.state == "open"
end

local function read_reply(socket)
  local ok, line = socket:receive_lines(1)
  if not ok or not line then return nil end
  return line:sub(1, 512)
end

action = function(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(math.max(100, math.min(tonumber(stdnse.get_script_args("agenttesla.timeout")) or 3000, 5000)))
  local ok, err = socket:connect(host.ip, port.number, "tcp")
  if not ok then socket:close(); return stdnse.format_output(false, err) end
  local banner = read_reply(socket)
  if not banner or not banner:match("^220") then socket:close(); return {
    family="agenttesla", protocol="ftp", c2_confirmed=false,
    confidence=0.20, status="ftp_banner_missing_or_invalid"}
  end
  local user = stdnse.get_script_args("agenttesla.user")
  local password = stdnse.get_script_args("agenttesla.pass")
  if not user or not password then
    socket:send("QUIT\r\n")
    socket:close()
    return {
      family="agenttesla", protocol="ftp", c2_confirmed=false,
      confidence=0.35, status="ftp_banner_only",
      banner_code=220, authentication_attempted=false,
      note="FTP bannerだけではAgentTesla固有C2を証明しません"
    }
  end
  if user:find("[\r\n]") or password:find("[\r\n]") or #user > 256 or #password > 256 then
    socket:close(); return stdnse.format_output(false, "FTP資格情報の形式が不正です")
  end
  socket:send("USER " .. user .. "\r\n")
  local user_reply = read_reply(socket) or ""
  local pass_reply = ""
  local accepted = user_reply:match("^230") ~= nil
  if not accepted and user_reply:match("^331") then
    socket:send("PASS " .. password .. "\r\n")
    pass_reply = read_reply(socket) or ""
    accepted = pass_reply:match("^230") ~= nil
  end
  socket:send("QUIT\r\n")
  socket:close()
  return {
    family="agenttesla", protocol="ftp", c2_confirmed=accepted,
    confidence=accepted and 0.95 or 0.45,
    status=accepted and "sample_credential_ftp_login_succeeded" or "ftp_login_rejected",
    banner_code=220, user_reply_code=tonumber(user_reply:sub(1,3)),
    pass_reply_code=tonumber(pass_reply:sub(1,3)),
    authentication_attempted=true, file_operation_attempted=false,
    credential_value_published=false
  }
end
