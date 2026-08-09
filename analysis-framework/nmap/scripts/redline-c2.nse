local match = require "match"
local nmap = require "nmap"
local openssl = require "openssl"
local slaxml = require "slaxml"
local stdnse = require "stdnse"

description = [[
RedLine Stealerのレビュー済みWCF BasicHttpBinding endpointへ、CheckConnect SOAP 1.1
requestを1回だけ送信します。対象、SOAPAction、path、bodyを固定し、redirect、端末登録、
task取得、task実行、payload取得は行いません。厳密なCheckConnectResult boolean応答だけを
C2確認済みとして扱います。
]]

author = "AI-security-analysis"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "malware", "discovery"}

portrule = function(_, port)
  return port.protocol == "tcp" and port.state == "open"
end

local SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"
local CONTRACT_NS = "http://tempuri.org/"
local SOAP_ACTION = "http://tempuri.org/Endpoint/CheckConnect"
local BODY = '<?xml version="1.0" encoding="utf-8"?>' ..
  '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">' ..
  '<s:Body><CheckConnect xmlns="http://tempuri.org/" /></s:Body></s:Envelope>'
local MAX_RESPONSE_BYTES = 4096
local MAX_HEADER_BYTES = 2048
local PRODUCTION_PROFILE = "redline-3f3ac0a3-checkconnect-v1"
local LOOPBACK_PROFILE = "redline-loopback-checkconnect-v1"
local PRODUCTION_REQUEST_SIZE = 357
local PRODUCTION_REQUEST_SHA256 =
  "dd8c02ce792cd8d4e9ce3e05c32ff19c8d1633d24312203b9ec5018645e45f33"

local function profile_target(profile_id, host, port)
  if profile_id == PRODUCTION_PROFILE then
    if host.ip ~= "192.144.32.84" or port.number ~= 16383 then
      return nil, "review済みRedLine profileのIPまたはportが一致しません"
    end
    return "192.144.32.84:16383", nil
  end
  if profile_id == LOOPBACK_PROFILE and
     (host.ip == "127.0.0.1" or host.ip == "::1") then
    return host.ip .. ":" .. port.number, nil
  end
  return nil, "既知のreview済みprofile、またはlocalhost専用試験profileが必要です"
end

local function build_request(host_header)
  return "POST / HTTP/1.1\r\n" ..
    "Host: " .. host_header .. "\r\n" ..
    "Content-Type: text/xml; charset=utf-8\r\n" ..
    'SOAPAction: "' .. SOAP_ACTION .. '"\r\n' ..
    "Content-Length: " .. #BODY .. "\r\n" ..
    "Connection: close\r\n\r\n" .. BODY
end

local function parse_headers(blob)
  if #blob > MAX_HEADER_BYTES or blob:sub(-4) ~= "\r\n\r\n" then
    return nil, "redline_http_header_out_of_bounds"
  end
  local framing_check = blob:gsub("\r\n", "")
  if framing_check:find("[\r\n]") then
    return nil, "redline_http_header_malformed"
  end
  local lines = {}
  for line in (blob:sub(1, -5) .. "\r\n"):gmatch("(.-)\r\n") do
    if line == "" then return nil, "redline_http_header_malformed" end
    lines[#lines + 1] = line
  end
  if #lines < 2 then return nil, "redline_http_header_malformed" end
  if lines[1]:find("[%z\1-\8\11\12\14-\31\127]") then
    return nil, "redline_http_status_line_malformed"
  end
  local status_text = lines[1]:match("^HTTP/1%.[01] ([0-9][0-9][0-9])")
  local status_rest = lines[1]:sub(13)
  if not status_text or (status_rest ~= "" and status_rest:sub(1, 1) ~= " ") then
    return nil, "redline_http_status_line_malformed"
  end
  local status = tonumber(status_text)
  local headers = {}
  for index = 2, #lines do
    local name, value = lines[index]:match("^([!#$%%&'*+%.%^_`|~%w-]+):[ \t]*(.-)[ \t]*$")
    if not name or value:find("[%z\1-\8\11\12\14-\31\127]") then
      return nil, "redline_http_header_malformed"
    end
    name = name:lower()
    if headers[name] ~= nil then return nil, "redline_http_duplicate_header" end
    headers[name] = value
  end
  if status < 200 or status > 299 then
    return nil, "redline_http_non_success_status"
  end
  if headers["transfer-encoding"] then
    return nil, "redline_transfer_encoding_rejected"
  end
  local content_type = headers["content-type"] and headers["content-type"]:lower() or ""
  if content_type ~= "text/xml; charset=utf-8" and
     content_type ~= 'text/xml; charset="utf-8"' then
    return nil, "redline_content_type_mismatch"
  end
  local length_text = headers["content-length"]
  if not length_text or not length_text:match("^[0-9]+$") then
    return nil, "redline_content_length_missing_or_invalid"
  end
  local length = tonumber(length_text)
  if not length or length < 1 or #blob + length > MAX_RESPONSE_BYTES then
    return nil, "redline_http_response_out_of_bounds"
  end
  return {status=status, content_length=length}, nil
end

local function parse_checkconnect(body)
  if body:find("<!", 1, true) or body:find("<!--", 1, true) then
    return nil
  end
  local without_declaration, count = body:gsub(
    '^%s*<%?xml%s+version=["\']1%.0["\']%s+encoding=["\']utf%-8["\']%s*%?>', "", 1)
  if count == 0 then without_declaration = body end
  if without_declaration:find("<?", 1, true) then return nil end
  local expected = {
    {"Envelope", SOAP_NS},
    {"Body", SOAP_NS},
    {"CheckConnectResponse", CONTRACT_NS},
    {"CheckConnectResult", CONTRACT_NS}
  }
  local stack = {}
  local starts = 0
  local value = nil
  local invalid = false
  local parser = slaxml.parser:new({
    startElement = function(name, namespace)
      starts = starts + 1
      local item = expected[starts]
      if not item or name ~= item[1] or namespace ~= item[2] then invalid = true end
      stack[#stack + 1] = {name, namespace}
    end,
    attribute = function(name)
      if name ~= "xmlns" and not name:match("^xmlns:") then invalid = true end
    end,
    text = function(text)
      local top = stack[#stack]
      local stripped = text:match("^%s*(.-)%s*$")
      if not top or top[1] ~= "CheckConnectResult" or value ~= nil or stripped == "" then
        invalid = true
      else
        value = stripped:lower()
      end
    end,
    comment = function() invalid = true end,
    pi = function() invalid = true end,
    closeElement = function(name, namespace)
      local top = stack[#stack]
      if not top or top[1] ~= name or top[2] ~= namespace then
        invalid = true
      else
        stack[#stack] = nil
      end
    end
  })
  local ok = pcall(function()
    parser:parseSAX(without_declaration, {stripWhitespace=true})
  end)
  if not ok or invalid or starts ~= 4 or #stack ~= 0 or not value then return nil end
  if value ~= "true" and value ~= "false" and value ~= "1" and value ~= "0" then
    return nil
  end
  return value == "true" or value == "1"
end

action = function(host, port)
  local profile_id = stdnse.get_script_args("redline.profile-id")
  local acknowledgement = stdnse.get_script_args("redline.acknowledge-profile")
  if not profile_id or acknowledgement ~= profile_id then
    return stdnse.format_output(false,
      "redline.profile-idと同値のredline.acknowledge-profileが必要です")
  end
  local host_header, profile_error = profile_target(profile_id, host, port)
  if not host_header then return stdnse.format_output(false, profile_error) end
  local timeout = math.max(100, math.min(
    tonumber(stdnse.get_script_args("redline.timeout")) or 3000, 5000))
  local request = build_request(host_header)
  if #request > 512 then
    return stdnse.format_output(false, "RedLine requestが512 byte上限を超えました")
  end
  if profile_id == PRODUCTION_PROFILE and
     (#request ~= PRODUCTION_REQUEST_SIZE or
      stdnse.tohex(openssl.digest("sha256", request)) ~= PRODUCTION_REQUEST_SHA256) then
    return stdnse.format_output(false,
      "RedLine production requestがreview済みbyte vectorと一致しません")
  end
  local socket = nmap.new_socket()
  socket:set_timeout(timeout)
  local ok, err = socket:connect(host.ip, port.number, "tcp")
  if not ok then socket:close(); return stdnse.format_output(false, err) end
  local sent, send_err = socket:send(request)
  if not sent then socket:close(); return stdnse.format_output(false, send_err) end
  local header_ok, header = socket:receive_buf(
    match.pattern_limit("\r\n\r\n", MAX_HEADER_BYTES), true)
  if not header_ok or not header then socket:close(); return {
    family="redlinestealer", protocol="wcf_soap11_checkconnect",
    c2_confirmed=false, confidence=0.0, status="redline_http_header_not_received",
    request_count=1, sent_bytes=#request, response_size=0,
    sample_executed=false, network_contacted=true, application_data_sent=true,
    redirect_followed=false, registration_attempted=false,
    task_poll_attempted=false, task_executed=false, payload_download_attempted=false}
  end
  local parsed, parse_error = parse_headers(header)
  if not parsed then socket:close(); return {
    family="redlinestealer", protocol="wcf_soap11_checkconnect",
    c2_confirmed=false, confidence=0.0, status=parse_error,
    request_count=1, sent_bytes=#request, response_size=#header,
    sample_executed=false, network_contacted=true, application_data_sent=true,
    redirect_followed=false, registration_attempted=false,
    task_poll_attempted=false, task_executed=false, payload_download_attempted=false}
  end
  local body_ok, response_body = socket:receive_buf(
    match.numbytes(parsed.content_length), true)
  socket:close()
  if not body_ok or not response_body or #response_body ~= parsed.content_length then
    return {
      family="redlinestealer", protocol="wcf_soap11_checkconnect",
      c2_confirmed=false, confidence=0.0, status="redline_http_body_truncated",
      request_count=1, sent_bytes=#request,
      response_size=#header + (response_body and #response_body or 0),
      sample_executed=false, network_contacted=true, application_data_sent=true,
      redirect_followed=false, registration_attempted=false,
      task_poll_attempted=false, task_executed=false, payload_download_attempted=false}
  end
  local result = parse_checkconnect(response_body)
  local matched = result ~= nil
  local result_text = nil
  if matched then result_text = result and "true" or "false" end
  return {
    family="redlinestealer", protocol="wcf_soap11_checkconnect",
    profile_id=profile_id, c2_confirmed=matched,
    confidence=matched and (result and 0.98 or 0.95) or 0.0,
    status=matched and (result and "redline_checkconnect_true_match" or
      "redline_checkconnect_false_match") or "redline_checkconnect_soap_mismatch",
    checkconnect_result=result_text,
    operational_checkconnect_accepted=matched and result or false,
    request_count=1, maximum_request_count=1, sent_bytes=#request,
    response_size=#header + #response_body, raw_response_published=false,
    sample_executed=false, network_contacted=true, application_data_sent=true,
    redirect_followed=false, victim_metadata_sent=false,
    registration_attempted=false, task_poll_attempted=false,
    task_content_published=false, task_executed=false,
    payload_download_attempted=false
  }
end
