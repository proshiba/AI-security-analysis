local nmap = require "nmap"
local openssl = require "openssl"
local stdnse = require "stdnse"
local zlib = require "zlib"

description = [[
中央profile未登録のC2候補を、TCP open、server-first banner、TLS handshake、または
単一HTTP GETのいずれかで限定観測します。TLS modeでは明示指定時に、clientから
application dataを送らずValleyRAT N520型44-byte server-first frameだけを検証できます。
汎用観測であるためc2_confirmedは常にfalseです。redirect、認証、登録、task取得は行いません。
]]

author = "AI-security-analysis"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "discovery"}

portrule = function(_, port)
  return port.protocol == "tcp" and port.state == "open"
end

local function timeout_ms()
  local value = tonumber(stdnse.get_script_args("c2-transport.timeout")) or 3000
  return math.max(100, math.min(value, 5000))
end

local function maximum_response_bytes(default_value)
  local value = tonumber(stdnse.get_script_args("c2-transport.max-response")) or default_value
  return math.max(1, math.min(value, 4096))
end

local function base(status)
  return {
    family="unclassified",
    c2_confirmed=false,
    probable_c2=false,
    confidence=0.15,
    status=status,
    network_contacted_by_nmap_scan=true,
    registration_attempted=false,
    task_poll_attempted=false,
    task_executed=false,
    payload_download_attempted=false,
    victim_metadata_sent=false
  }
end

local function tcp_open()
  local result = base("tcp_open_only")
  result.protocol = "tcp_transport_only"
  result.target_connection_established = true
  result.application_data_sent = false
  result.sent_bytes = 0
  result.request_count = 0
  return result
end

local function banner(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(timeout_ms())
  local ok, err = socket:connect(host.ip, port.number, "tcp")
  if not ok then socket:close(); return stdnse.format_output(false, err) end
  local limit = maximum_response_bytes(256)
  local received, value = socket:receive_bytes(limit)
  socket:close()
  local result = base(received and "server_first_banner_observed" or "server_first_banner_missing")
  result.protocol = "server_first_transport_only"
  result.target_connection_established = true
  result.application_data_sent = false
  result.sent_bytes = 0
  result.request_count = 0
  result.received_bytes = value and #value or 0
  result.banner_length = value and #value or 0
  result.ftp_220_marker = value and value:sub(1, 3) == "220" or false
  return result
end

local function tls(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(timeout_ms())
  local ok, err = socket:connect(host.ip, port.number, "ssl")
  if not ok then socket:close(); return stdnse.format_output(false, err) end
  local certificate = socket:get_ssl_certificate()
  local digest_sha1 = certificate and stdnse.tohex(certificate:digest("sha1")) or nil
  local digest = certificate and stdnse.tohex(certificate:digest("sha256")) or nil
  local observe_n520 = stdnse.get_script_args("c2-transport.observe-n520-server-first") == "true"
  local received, response = false, nil
  if observe_n520 then
    received, response = socket:receive_bytes(7)
    if response and response ~= "TIMEOUT" and #response < 44 then
      local remaining_received, remaining = socket:receive_bytes(44 - #response)
      if remaining then
        response = response .. remaining
        received = received and remaining_received
      end
    end
  end
  socket:close()
  local result = base("tls_handshake_observed")
  result.protocol = "tls_transport_only"
  result.confidence = 0.35
  result.target_connection_established = true
  result.application_data_sent = false
  result.sent_bytes = 0
  result.request_count = 0
  result.certificate_sha1 = digest_sha1
  result.certificate_sha256 = digest
  result.tls_version_enforced_by_nse = false
  result.certificate_mismatch_excludes_c2 = false
  if observe_n520 then
    result.received_bytes = response and #response or 0
    if response then
      result.response_sha256 = stdnse.tohex(openssl.digest("sha256", response))
      result.response_printable_ascii = not response:find("[^%g ]")
    end
    if response == "TIMEOUT" then
      result.status = "tls_server_first_timeout_marker"
      result.timeout_marker_matches = true
      result.confidence = 0.45
    elseif response and #response == 44 then
      local session_id, received_magic = string.unpack("<I4I4", response)
      local mixed = (((session_id >> 16) ~ (session_id & 0xffff)) | 0xa5a50000) & 0xffffffff
      local expected_magic = (session_id ~ mixed) & 0xffffffff
      local stored_crc = string.unpack("<I4", response, 41)
      local calculated_crc = zlib.crc32(zlib.crc32(), response:sub(1, 40)) & 0xffffffff
      local matched = received_magic == expected_magic and stored_crc == calculated_crc
      result.family = matched and "valleyrat" or "unclassified"
      result.probable_c2 = matched
      result.confidence = matched and 0.90 or 0.35
      result.status = matched and "n520_server_first_handshake_match" or "n520_handshake_mismatch"
      result.session_id = string.format("0x%08x", session_id)
      result.magic_matches = received_magic == expected_magic
      result.crc_matches = stored_crc == calculated_crc
    elseif not response or #response == 0 then
      result.status = "n520_server_first_handshake_missing"
    else
      result.status = "n520_server_first_handshake_length_mismatch"
    end
  end
  return result
end

local function valid_http_path(value)
  return value and #value >= 1 and #value <= 512 and value:sub(1, 1) == "/" and
    not value:find("[\r\n%z]")
end

local function valid_http_host(value)
  return value and #value >= 1 and #value <= 253 and not value:find("[^A-Za-z0-9%.:%-%[%]]")
end

local function http_get(host, port)
  local path = stdnse.get_script_args("c2-transport.path") or "/"
  local host_header = stdnse.get_script_args("c2-transport.host") or host.targetname or host.ip
  if not valid_http_path(path) or not valid_http_host(host_header) then
    return stdnse.format_output(false, "HTTP pathまたはHostが安全境界外です")
  end
  local socket = nmap.new_socket()
  socket:set_timeout(timeout_ms())
  local protocol = stdnse.get_script_args("c2-transport.http-tls") == "true" and "ssl" or "tcp"
  local ok, err = socket:connect(host.ip, port.number, protocol)
  if not ok then socket:close(); return stdnse.format_output(false, err) end
  local request = "GET " .. path .. " HTTP/1.1\r\nHost: " .. host_header ..
    "\r\nUser-Agent: AI-security-analysis-NSE/1\r\nConnection: close\r\n\r\n"
  if #request > 1024 then socket:close(); return stdnse.format_output(false, "HTTP request上限超過") end
  local sent, send_err = socket:send(request)
  if not sent then socket:close(); return stdnse.format_output(false, send_err) end
  local limit = maximum_response_bytes(4096)
  local received, value = socket:receive_bytes(limit)
  socket:close()
  local status = value and tonumber(value:match("^HTTP/%d+%.%d+%s+(%d%d%d)")) or nil
  local result = base(status and "http_response_observed" or "http_response_missing_or_invalid")
  result.protocol = protocol == "ssl" and "https_transport_only" or "http_transport_only"
  result.confidence = status and 0.45 or 0.15
  result.target_connection_established = true
  result.application_data_sent = true
  result.sent_bytes = #request
  result.request_count = 1
  result.received_bytes = value and #value or 0
  result.response_size = value and #value or 0
  result.http_status = status
  result.redirect_followed = false
  return result
end

action = function(host, port)
  local mode = stdnse.get_script_args("c2-transport.mode")
  if mode == "tcp-open" then return tcp_open() end
  if mode == "server-first" then return banner(host, port) end
  if mode == "tls" then return tls(host, port) end
  if mode == "http-get" then return http_get(host, port) end
  return stdnse.format_output(false,
    "--script-args c2-transport.mode=tcp-open|server-first|tls|http-get が必要です")
end
