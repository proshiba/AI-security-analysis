local nmap = require "nmap"
local match = require "match"
local openssl = require "openssl"
local stdnse = require "stdnse"

description = [[
0f2 PureLogsケースでレビュー済みの単一endpointだけへ、証明書pin確認後に
HTTPS GET /pingを1回送信します。profile ID、同値acknowledgement、固定host、
固定IP、port、期待証明書がすべて一致しない限りapplication dataを送信しません。
redirectは追跡せず、応答は最大1 KiBです。HTTP 200かつ本文が厳密にOKでも
probable判定に限定し、c2_confirmedは常にfalseです。

http_aes_v5という世代分類はfamily-levelの公開調査に基づき、このsampleのversion
確定を意味しません。legacy_socket_3des codecは本NSEへ実装していません。

Nmap socket APIではTLS 1.2だけを厳密に強制したことを検証できないため、結果へ
tls_version_enforced_by_nse=falseを明示します。
]]

author = "AI-security-analysis"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "malware", "discovery"}

local PROFILE_ID = "purelogs-0f2abaab-logs-uvexio-8443-ping-v1"
local SAMPLE_SHA256 = "0f2abaabea8bb9454e5cf979e58eba7de10172dab1f3ebff6a9face304f4ce48"
local REVIEWED_HOST = "logs.uvexio.com"
local REVIEWED_IP = "193.26.115.118"
local REVIEWED_PORT = 8443
local EXPECTED_CERTIFICATE_SHA256 =
  "9e254cab8c68944cea18a3ac5523fe491eb14f9447b352dca33729b64eaeeac3"
local EXPECTED_RESPONSE_SHA256 =
  "565339bc4d33d72817b583024112eb7f5cdf3e5eef0252d6ec1b9c9a94e12bb3"
local MAX_REQUEST_BYTES = 256
local MAX_RESPONSE_BYTES = 1024
local MAX_HEADER_BYTES = MAX_RESPONSE_BYTES - 2

portrule = function(_, port)
  return port.protocol == "tcp" and port.state == "open" and
    port.number == REVIEWED_PORT
end

local function base_result()
  return {
    family="purelogs",
    variant="http_aes_v5",
    generation_evidence_scope="family_level_public_research",
    sample_version_confirmed=false,
    excluded_variant="legacy_socket_3des",
    legacy_codec_implemented=false,
    profile_id=PROFILE_ID,
    sample_sha256=SAMPLE_SHA256,
    protocol="purelogs_https_ping",
    c2_confirmed=false,
    probable_c2=false,
    confidence=0.0,
    reviewed_host=REVIEWED_HOST,
    reviewed_ip=REVIEWED_IP,
    reviewed_port=REVIEWED_PORT,
    http_method="GET",
    http_path="/ping",
    tls_version_expected="TLSv1.2",
    tls_version_enforced_by_nse=false,
    redirect_followed=false,
    response_body_published=false,
    raw_response_published=false,
    response_hash_scope="http_body",
    request_body_sent=false,
    victim_metadata_sent=false,
    registration_attempted=false,
    task_poll_attempted=false,
    task_executed=false,
    payload_download_attempted=false,
    request_count=0,
    sent_bytes=0,
    received_bytes=0,
    application_data_sent=false,
    target_contact_attempted_by_script=false
  }
end

local function parse_response(header_with_boundary, body)
  if not header_with_boundary or #header_with_boundary < 4 or
     #header_with_boundary > MAX_HEADER_BYTES or
     header_with_boundary:sub(-4) ~= "\r\n\r\n" then
    return nil, "purelogs_ping_header_out_of_bounds"
  end
  if not body or #body ~= 2 or #header_with_boundary + #body > MAX_RESPONSE_BYTES then
    return nil, "purelogs_ping_body_length_mismatch"
  end
  local header_blob = header_with_boundary:sub(1, -5)
  local lines = {}
  for line in (header_blob .. "\r\n"):gmatch("(.-)\r\n") do
    if line == "" then return nil, "purelogs_ping_header_malformed" end
    lines[#lines + 1] = line
  end
  local status_text = lines[1] and lines[1]:match(
    "^HTTP/1%.[01] ([0-9][0-9][0-9]) [^\r\n]+$") or nil
  if not status_text then return nil, "purelogs_ping_status_malformed" end
  local headers = {}
  for index = 2, #lines do
    if lines[index]:find("[%z\1-\8\11\12\14-\31\127]") then
      return nil, "purelogs_ping_header_control_character"
    end
    local name, value = lines[index]:match("^([!#$%%&'*+.^_`|~%w-]+):[ \t]*(.-)[ \t]*$")
    if not name then return nil, "purelogs_ping_header_malformed" end
    name = name:lower()
    if headers[name] ~= nil then return nil, "purelogs_ping_duplicate_header" end
    headers[name] = value
  end
  if headers["transfer-encoding"] or headers["content-encoding"] then
    return nil, "purelogs_ping_unsupported_encoding"
  end
  if headers["content-length"] ~= "2" or #body ~= 2 then
    return nil, "purelogs_ping_body_length_mismatch"
  end
  return {
    status=tonumber(status_text),
    body_exact=body == "OK",
    response_sha256=stdnse.tohex(openssl.digest("sha256", body)),
    response_size=#header_with_boundary + #body
  }, nil
end

action = function(host, port)
  local result = base_result()
  local profile_id = stdnse.get_script_args("purelogs.profile-id")
  local acknowledgement = stdnse.get_script_args("purelogs.acknowledge-profile")
  local expected_host = stdnse.get_script_args("purelogs.expected-host")
  local expected_ip = stdnse.get_script_args("purelogs.expected-ip")
  local expected_certificate = stdnse.get_script_args("purelogs.expected-cert")
  if profile_id ~= PROFILE_ID or acknowledgement ~= PROFILE_ID or
     expected_host ~= REVIEWED_HOST or expected_ip ~= REVIEWED_IP or
     expected_certificate ~= EXPECTED_CERTIFICATE_SHA256 or
     host.ip ~= REVIEWED_IP or port.number ~= REVIEWED_PORT then
    result.status = "purelogs_reviewed_profile_gate_failed"
    result.profile_acknowledged = false
    return result
  end
  result.profile_acknowledged = true
  result.target_endpoint_exact_match = true

  local socket = nmap.new_socket()
  socket:set_timeout(math.max(100, math.min(
    tonumber(stdnse.get_script_args("purelogs.timeout")) or 3000, 5000)))
  result.target_contact_attempted_by_script = true
  local connected, connect_error = socket:connect(host.ip, port.number, "ssl")
  if not connected then
    socket:close()
    result.status = "purelogs_tls_handshake_failed"
    result.error = connect_error
    return result
  end
  local certificate = socket:get_ssl_certificate()
  local observed = certificate and stdnse.tohex(certificate:digest("sha256")) or nil
  local certificate_exact = observed and
    observed:lower() == EXPECTED_CERTIFICATE_SHA256 or false
  result.certificate_sha256 = observed
  result.certificate_exact_match = certificate_exact
  if not certificate_exact then
    socket:close()
    result.status = "purelogs_certificate_mismatch_no_request_sent"
    return result
  end

  local request = "GET /ping HTTP/1.1\r\nHost: " .. REVIEWED_HOST ..
    "\r\nUser-Agent: AI-security-analysis-PureLogs-NSE/1\r\n" ..
    "Accept: text/plain\r\nConnection: close\r\n\r\n"
  if #request > MAX_REQUEST_BYTES then
    socket:close()
    result.status = "purelogs_request_out_of_bounds"
    return result
  end
  local sent, send_error = socket:send(request)
  if not sent then
    socket:close()
    result.status = "purelogs_ping_send_failed"
    result.error = send_error
    return result
  end
  result.application_data_sent = true
  result.request_count = 1
  result.sent_bytes = #request
  local header_ok, response_header = socket:receive_buf(
    match.pattern_limit("\r\n\r\n", MAX_HEADER_BYTES), true)
  if not header_ok then
    socket:close()
    result.status = "purelogs_ping_header_not_received"
    return result
  end
  local body_ok, response_body = socket:receive_bytes(2)
  socket:close()
  result.received_bytes = (response_header and #response_header or 0) +
    (response_body and #response_body or 0)
  if not body_ok then
    result.status = "purelogs_ping_body_not_received"
    return result
  end
  local parsed, parse_error = parse_response(response_header, response_body)
  if not parsed then
    result.status = parse_error
    return result
  end
  result.http_status = parsed.status
  result.response_size = parsed.response_size
  result.response_sha256 = parsed.response_sha256
  result.body_exact_match = parsed.body_exact
  local matched = parsed.status == 200 and parsed.body_exact and
    parsed.response_sha256 == EXPECTED_RESPONSE_SHA256
  result.status = matched and "purelogs_ping_probable_match" or
    "purelogs_ping_response_mismatch"
  result.probable_c2 = matched
  result.c2_confirmed = false
  result.confidence = matched and 0.70 or 0.0
  return result
end
