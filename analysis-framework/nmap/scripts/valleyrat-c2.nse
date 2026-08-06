local nmap = require "nmap"
local stdnse = require "stdnse"
local zlib = require "zlib"

description = [[
ValleyRAT/Winos系C2のレビュー済み最小プローブを送信し、応答フレームを検証します。
modeはwinos、vvas、n520のいずれかを明示する必要があります。stage取得、端末登録、
任意command送信は行いません。
]]

author = "AI-security-analysis"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "malware", "discovery"}

portrule = function(_, port)
  return port.protocol == "tcp" and port.state == "open"
end

local function timeout_ms()
  local value = tonumber(stdnse.get_script_args("valleyrat.timeout")) or 3000
  return math.max(100, math.min(value, 5000))
end

local function connect(host, port, protocol)
  local socket = nmap.new_socket()
  socket:set_timeout(timeout_ms())
  local ok, err = socket:connect(host.ip, port.number, protocol)
  if not ok then
    socket:close()
    return nil, err
  end
  return socket
end

local function xor_payload(data, header)
  local output = {}
  for index = 1, #data do
    local header_index = index == 1 and 1 or (((index - 2) % 10) + 1)
    local mask = (header:byte(header_index) + 0x36) & 0xff
    output[index] = string.char(data:byte(index) ~ mask)
  end
  return table.concat(output)
end

local function winos(host, port)
  local socket, err = connect(host, port, "tcp")
  if not socket then return stdnse.format_output(false, err) end
  local header = string.pack("<I4I4I2", 0x12345678, 0, 0x00ca)
  local frame = string.pack("<I4", 15) .. header .. xor_payload(string.char(0xc9), header)
  local sent, send_err = socket:send(frame)
  if not sent then socket:close(); return stdnse.format_output(false, send_err) end
  local status, response = socket:receive_bytes(15)
  socket:close()
  if not status or not response or #response < 15 then
    return {family="valleyrat", protocol="winos", c2_confirmed=false,
      confidence=0.40, status="heartbeat_response_missing"}
  end
  local declared = string.unpack("<I4", response)
  if declared < 15 or declared > 64 or #response < declared then
    return {family="valleyrat", protocol="winos", c2_confirmed=false,
      confidence=0.30, status="invalid_winos_frame"}
  end
  local response_header = response:sub(5, 14)
  local payload = xor_payload(response:sub(15, declared), response_header)
  local command = payload:byte(1)
  local matched = command == 0xc9 or command == 0xca or command == 0xcb
  return {
    family="valleyrat", protocol="winos", c2_confirmed=matched,
    confidence=matched and 0.95 or 0.45,
    status=matched and "winos_control_response" or "winos_unknown_response",
    response_command=command and string.format("0x%02x", command) or nil,
    declared_length=declared, sent_bytes=#frame, received_bytes=#response,
    victim_metadata_sent=false, stage_requested=false
  }
end

local function vvas(host, port)
  local socket, err = connect(host, port, "tcp")
  if not socket then return stdnse.format_output(false, err) end
  local sent, send_err = socket:send(string.char(0x33, 0x32, 0x00))
  if not sent then socket:close(); return stdnse.format_output(false, send_err) end
  local status, response = socket:receive_bytes(14)
  socket:close()
  if not status or not response or #response < 14 then
    return {family="valleyrat", protocol="vvas", c2_confirmed=false,
      confidence=0.40, status="vvas_header_missing"}
  end
  local size = string.unpack("<I4", response)
  local zeros = response:sub(5, 14) == string.rep("\0", 10)
  local matched = size == 307214 and zeros
  return {
    family="valleyrat", protocol="vvas", c2_confirmed=matched,
    confidence=matched and 0.95 or 0.35,
    status=matched and "vvas_stage_header_match" or "vvas_header_mismatch",
    declared_stage_size=size, expected_stage_size=307214,
    sent_bytes=3, received_bytes=#response, stage_downloaded=false,
    victim_metadata_sent=false
  }
end

local function n520(host, port)
  local socket, err = connect(host, port, "ssl")
  if not socket then return stdnse.format_output(false, err) end
  local status, response = socket:receive_bytes(44)
  socket:close()
  if not status or not response or #response ~= 44 then
    return {family="valleyrat", protocol="n520", c2_confirmed=false,
      confidence=0.40, status="n520_handshake_missing"}
  end
  local session_id, received_magic = string.unpack("<I4I4", response)
  local mixed = (((session_id >> 16) ~ (session_id & 0xffff)) | 0xa5a50000) & 0xffffffff
  local expected_magic = (session_id ~ mixed) & 0xffffffff
  local stored_crc = string.unpack("<I4", response, 41)
  local calculated_crc = zlib.crc32(zlib.crc32(), response:sub(1, 40)) & 0xffffffff
  local matched = received_magic == expected_magic and stored_crc == calculated_crc
  return {
    family="valleyrat", protocol="n520", c2_confirmed=matched,
    confidence=matched and 0.98 or 0.35,
    status=matched and "n520_server_first_handshake_match" or "n520_handshake_mismatch",
    session_id=string.format("0x%08x", session_id),
    magic_matches=received_magic == expected_magic,
    crc_matches=stored_crc == calculated_crc,
    application_data_sent=false, received_bytes=#response
  }
end

action = function(host, port)
  local mode = stdnse.get_script_args("valleyrat.mode")
  if mode == "winos" then return winos(host, port) end
  if mode == "vvas" then return vvas(host, port) end
  if mode == "n520" then return n520(host, port) end
  return stdnse.format_output(false, "--script-args valleyrat.mode=winos|vvas|n520 が必要です")
end
