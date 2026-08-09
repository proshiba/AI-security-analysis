local base64 = require "base64"
local match = require "match"
local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
DarkCometのレビュー済み完全一致endpointからserver-first challengeを受信し、検体から
静的復元したRC4 network keyで復号します。raw 6 byteまたはASCII-hex 12 byteを厳格に
解析し、平文がIDTYPEへ完全一致した場合だけC2と判定します。application dataは送信しません。
DNS解決はNmap本体の範囲で、scriptの単一期限は接続開始から受信終了までに適用します。
]]

author = "AI-security-analysis"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "malware", "discovery"}

portrule = function(_, port)
  return port.protocol == "tcp" and port.state == "open"
end

local function rc4(data, key)
  if #key < 1 or #key > 256 then return nil end
  local state = {}
  for index = 0, 255 do state[index] = index end
  local right = 0
  for left = 0, 255 do
    right = (right + state[left] + key:byte((left % #key) + 1)) & 0xff
    state[left], state[right] = state[right], state[left]
  end
  local left = 0
  right = 0
  local output = {}
  for offset = 1, #data do
    left = (left + 1) & 0xff
    right = (right + state[left]) & 0xff
    state[left], state[right] = state[right], state[left]
    output[offset] = string.char(data:byte(offset) ~ state[(state[left] + state[right]) & 0xff])
  end
  return table.concat(output)
end

local function bounded_receive(socket, deadline)
  local chunks = {}
  local length = 0
  while length <= 12 do
    local remaining = deadline - nmap.clock_ms()
    if remaining <= 0 then break end
    socket:set_timeout(math.max(1, remaining))
    local ok, value = socket:receive_buf(match.numbytes(1), true)
    if not ok or not value then break end
    chunks[#chunks + 1] = value
    length = length + #value
  end
  return table.concat(chunks)
end

local function decode_wire(wire)
  if #wire == 0 then return nil, nil, "connected_no_response" end
  if #wire == 6 then return wire, "raw", nil end
  if #wire == 12 and not wire:find("[^0-9A-Fa-f]") then
    local output = {}
    for offset = 1, 12, 2 do
      output[#output + 1] = string.char(tonumber(wire:sub(offset, offset + 1), 16))
    end
    return table.concat(output), "ascii_hex", nil
  end
  if #wire > 12 then return nil, nil, "darkcomet_ciphertext_overlong" end
  if #wire < 6 or (#wire < 12 and not wire:find("[^0-9A-Fa-f]")) then
    return nil, nil, "darkcomet_ciphertext_partial"
  end
  return nil, nil, "darkcomet_ciphertext_malformed"
end

action = function(host, port)
  local encoded_key = stdnse.get_script_args("darkcomet.key-base64")
  if not encoded_key then
    return stdnse.format_output(false, "review済みprofileのdarkcomet.key-base64が必要です")
  end
  local key_ok, key = pcall(base64.dec, encoded_key)
  if not key_ok or not key or #key < 1 or #key > 256 then
    return stdnse.format_output(false, "DarkComet RC4 keyが安全境界外です")
  end
  local timeout = math.max(100, math.min(tonumber(stdnse.get_script_args("darkcomet.timeout")) or 3000, 5000))
  local socket = nmap.new_socket()
  socket:set_timeout(timeout)
  local deadline = nmap.clock_ms() + timeout
  local ok, err = socket:connect(host.ip, port.number, "tcp")
  if not ok then socket:close(); return stdnse.format_output(false, err) end
  local wire = bounded_receive(socket, deadline)
  socket:close()
  local ciphertext, encoding, parse_status = decode_wire(wire)
  if not ciphertext then
    return {
      family="darkcomet", protocol="rc4_server_first", c2_confirmed=false,
      confidence=0.0, status=parse_status or "connected_no_response",
      received_bytes=#wire, server_first_bytes_received=#wire,
      application_data_sent=false, sent_bytes=0, decrypted_plaintext_published=false,
      rc4_key_published=false, victim_metadata_sent=false, stage_requested=false,
      dns_timeout_bounded=false, deadline_scope="post_dns_connect_receive"
    }
  end
  local plain = rc4(ciphertext, key)
  local matched = plain == "IDTYPE"
  return {
    family="darkcomet", protocol="rc4_server_first", c2_confirmed=matched,
    confidence=matched and 0.98 or 0.0,
    status=matched and "darkcomet_server_first_idtype_match" or "darkcomet_idtype_mismatch",
    wire_encoding=encoding, received_bytes=#wire, server_first_bytes_received=#wire,
    application_data_sent=false, sent_bytes=0, decrypted_plaintext_published=false,
    rc4_key_published=false, victim_metadata_sent=false, stage_requested=false,
    dns_timeout_bounded=false, deadline_scope="post_dns_connect_receive"
  }
end
