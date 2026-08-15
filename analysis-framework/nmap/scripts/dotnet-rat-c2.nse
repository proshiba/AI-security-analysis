local nmap = require "nmap"
local stdnse = require "stdnse"
local zlib = require "zlib"

description = [[
AsyncRATまたはVenomRATへTLS接続し、匿名の空Message Pingを1 frameだけ送信します。
圧縮MessagePack応答のpacket名まで一致した場合だけC2を確認済みとします。証明書不一致は
build差分やrotationがあり得るため、非C2の根拠にはしません。
]]

author = "AI-security-analysis"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "malware", "discovery"}

portrule = function(_, port)
  return port.protocol == "tcp" and port.state == "open"
end

local function pack_string(value)
  assert(#value <= 31)
  return string.char(0xa0 | #value) .. value
end

local function gzip(data)
  local deflated = zlib.compress(data, 9, 8, -15, 8, 0)
  local crc = zlib.crc32(zlib.crc32(), data) & 0xffffffff
  return string.char(0x1f,0x8b,0x08,0,0,0,0,0,0,0xff) .. deflated ..
    string.pack("<I4I4", crc, #data)
end

local function read_string(data, offset)
  local prefix = data:byte(offset)
  if not prefix then return nil, offset end
  local size
  if prefix >= 0xa0 and prefix <= 0xbf then
    size = prefix & 0x1f
    offset = offset + 1
  elseif prefix == 0xd9 then
    size = data:byte(offset + 1)
    offset = offset + 2
  else
    return nil, offset
  end
  if offset + size - 1 > #data then return nil, offset end
  return data:sub(offset, offset + size - 1), offset + size
end

local function decode_map(data)
  local prefix = data:byte(1)
  if not prefix or prefix < 0x81 or prefix > 0x8f then return nil end
  local count, offset, result = prefix & 0x0f, 2, {}
  for _ = 1, count do
    local key; key, offset = read_string(data, offset)
    if not key then return nil end
    local value; value, offset = read_string(data, offset)
    if not value then return nil end
    result[key] = value
  end
  if offset ~= #data + 1 then return nil end
  return result
end

action = function(host, port)
  local family = stdnse.get_script_args("dotnet-rat.family")
  local packet_key, expected
  if family == "asyncrat" then packet_key, expected = "Packet", "pong"
  elseif family == "venomrat" then packet_key, expected = "Pac_ket", "Po_ng"
  else return stdnse.format_output(false, "--script-args dotnet-rat.family=asyncrat|venomrat が必要です") end

  local socket = nmap.new_socket()
  socket:set_timeout(math.max(100, math.min(tonumber(stdnse.get_script_args("dotnet-rat.timeout")) or 3000, 5000)))
  local ok, err = socket:connect(host.ip, port.number, "ssl")
  if not ok then socket:close(); return stdnse.format_output(false, err) end
  local cert = socket:get_ssl_certificate()
  local cert_sha256 = cert and stdnse.tohex(cert:digest("sha256")) or nil
  local expected_cert = stdnse.get_script_args("dotnet-rat.expected-cert")
  local cert_match = nil
  if expected_cert and cert_sha256 then
    cert_match = expected_cert:lower() == cert_sha256:lower()
  end

  local raw = string.char(0x82) .. pack_string(packet_key) .. pack_string("Ping") ..
    pack_string("Message") .. pack_string("")
  local compressed = string.pack("<I4", #raw) .. gzip(raw)
  local frame = string.pack("<I4", #compressed) .. compressed
  if #frame > 96 then socket:close(); return stdnse.format_output(false, "request上限96 bytesを超えました") end
  local sent, send_err = socket:send(frame)
  if not sent then socket:close(); return stdnse.format_output(false, send_err) end
  local h_ok, header = socket:receive_bytes(4)
  if not h_ok or not header or #header < 4 then socket:close(); return {
    family=family, c2_confirmed=false, confidence=0.50, status="tls_only_no_messagepack_response",
    certificate_sha256=cert_sha256, certificate_mismatch_excludes_c2=false}
  end
  local declared = string.unpack("<I4", header)
  if declared < 5 or declared > 64 then socket:close(); return {
    family=family, c2_confirmed=false, confidence=0.45, status="response_length_out_of_bounds",
    declared_length=declared, certificate_sha256=cert_sha256,
    certificate_mismatch_excludes_c2=false}
  end
  local payload = header:sub(5)
  if #payload < declared then
    local p_ok, remainder = socket:receive_bytes(declared - #payload)
    if not p_ok or not remainder then socket:close(); return {
      family=family, c2_confirmed=false, confidence=0.45, status="truncated_messagepack_response",
      certificate_sha256=cert_sha256, certificate_mismatch_excludes_c2=false}
    end
    payload = payload .. remainder
  end
  socket:close()
  if #payload < declared then return {
    family=family, c2_confirmed=false, confidence=0.45, status="truncated_messagepack_response",
    certificate_sha256=cert_sha256, certificate_mismatch_excludes_c2=false}
  end
  payload = payload:sub(1, declared)
  local raw_size = string.unpack("<I4", payload)
  local inflate_ok, decoded = pcall(zlib.decompress, payload:sub(5), 31)
  local values = inflate_ok and decoded and #decoded == raw_size and decode_map(decoded) or nil
  local packet = values and values[packet_key] or nil
  local matched = packet == expected
  return {
    family=family, protocol="tls_compressed_messagepack", c2_confirmed=matched,
    confidence=matched and 0.98 or 0.55,
    status=matched and "messagepack_ping_response_match" or "messagepack_response_mismatch",
    response_packet=packet, sent_bytes=#frame, received_bytes=4+#payload,
    application_data_sent=true, request_count=1,
    certificate_sha256=cert_sha256, certificate_exact_match=cert_match,
    certificate_mismatch_excludes_c2=false, victim_metadata_sent=false,
    operation_command_sent=false, command_polling_performed=false,
    registration_attempted=false, task_poll_attempted=false,
    task_executed=false, payload_download_attempted=false
  }
end
