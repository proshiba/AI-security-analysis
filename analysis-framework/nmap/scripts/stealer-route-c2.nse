local match = require "match"
local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
FormBook、Vidar、AMOSについて、静的解析でレビュー済みのHTTP経路だけをHEAD要求で照合します。
profile ID、同値のacknowledgement、数値IPの明示pinがすべて一致する場合だけ通信します。
要求body、query、cookie、端末情報、認証情報、登録値は送信せず、redirectも追跡しません。
経路一致はprobable判定に限定し、c2_confirmedは常にfalseです。
]]

author = "AI-security-analysis"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "malware", "discovery"}

portrule = function(_, port)
  return port.protocol == "tcp" and port.state == "open"
end

local MAX_HEADER_BYTES = 4096
local MAX_REQUEST_BYTES = 512
local CONTROL_PATH = "/.well-known/asa-reviewed-route-negative-control-7f6d9e2b"
local RESEARCH_USER_AGENT = "AI-security-analysis reviewed-route probe/1.0"
local VIDAR_USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win32) AppleWebKit/537.36 (KHTML, like Gecko) Edg/147.0.0.0"
local FORMBOOK_USER_AGENT =
  "Mozilla/5.0 (Linux; U; Android 4.1.2; en-us; Xoom Build/JZO54M) " ..
  "AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Safari/534.30"

local PROFILES = {
  ["formbook-guloader-3f79-bootstrap-route-v1"] = {
    family="formbook", mode="formbook", host_header="www.plantaonewsms.com.br", port=80,
    sample_sha256="3f79dba83a2059c77f593c3247acf8f3d2b4c3e8a60f9ba1a656d0c04e600948",
    evidence_source="guloader_xloader_static_bootstrap_record_12",
    tls=false, paths={"/ximu/", CONTROL_PATH}, user_agent=FORMBOOK_USER_AGENT,
    confidence=0.60, loopback=false
  },
  ["formbook-loopback-route-v1"] = {
    family="formbook", mode="formbook", host_header="loopback.test", port=0,
    tls=false, paths={"/a1b2/", CONTROL_PATH}, user_agent=FORMBOOK_USER_AGENT,
    confidence=0.60, loopback=true
  },
  ["vidar-3bb64d86-direct-route-v1"] = {
    family="vidar", mode="vidar", host_header="195.201.45.175", port=443,
    sample_sha256="3bb64d86bed8337443f4b6f6c981914dd7d94b6fa7b61709015f9698e13bc67c",
    evidence_source="vidar_handler_result",
    tls=true, paths={"/", CONTROL_PATH}, user_agent=VIDAR_USER_AGENT,
    confidence=0.60, loopback=false
  },
  ["vidar-loopback-route-v1"] = {
    family="vidar", mode="vidar", host_header="loopback.test", port=0,
    tls=false, paths={"/", CONTROL_PATH}, user_agent=VIDAR_USER_AGENT,
    confidence=0.60, loopback=true
  },
  ["amos-nvoaagent-ledger-route-v1"] = {
    family="amosstealer", mode="amos", host_header="nvoaagent.com", port=443,
    sample_sha256="6f33360d3a3dc60454a64d74e1ac586f6a184b3886df46471b10e520c5fe0644",
    evidence_source="amos_embedded_https_pair",
    tls=true,
    paths={
      "/ledger/93ea36a257de15f2fe3f9d5d32fb19ee6e040fa3cd57131dedc33c740d868a89",
      "/ledger/live/93ea36a257de15f2fe3f9d5d32fb19ee6e040fa3cd57131dedc33c740d868a89",
      CONTROL_PATH
    },
    user_agent=RESEARCH_USER_AGENT, confidence=0.65, loopback=false
  },
  ["amos-flwoagent-ledger-route-v1"] = {
    family="amosstealer", mode="amos", host_header="flwoagent.com", port=443,
    sample_sha256="8809d3421c09669f88330adf3007b933abec13bf6ed105a785a97c7df2625301",
    evidence_source="amos_embedded_https_pair",
    tls=true,
    paths={
      "/ledger/484e513fdf967e35d2e21b8b88df0a2867c1abf6045e4ec41974ae927abb2140",
      "/ledger/live/484e513fdf967e35d2e21b8b88df0a2867c1abf6045e4ec41974ae927abb2140",
      CONTROL_PATH
    },
    user_agent=RESEARCH_USER_AGENT, confidence=0.65, loopback=false
  },
  ["amos-northernvirginiapainting-ledger-route-v1"] = {
    family="amosstealer", mode="amos", host_header="northernvirginiapainting.com", port=443,
    sample_sha256="47cd98c6ae435a1a6aa518e29f9e407ca42c82c9f4b86ceee93cc85d7feeae98",
    evidence_source="amos_embedded_https_pair",
    tls=true,
    paths={
      "/ledger/2fc78a36ea00d10a6d4fbba34bd924464f978f9598d97014a4a78a90eb3c6525",
      "/ledger/live/2fc78a36ea00d10a6d4fbba34bd924464f978f9598d97014a4a78a90eb3c6525",
      CONTROL_PATH
    },
    user_agent=RESEARCH_USER_AGENT, confidence=0.65, loopback=false
  },
  ["amos-loopback-ledger-route-v1"] = {
    family="amosstealer", mode="amos", host_header="loopback.test", port=0,
    tls=false,
    paths={
      "/ledger/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "/ledger/live/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      CONTROL_PATH
    },
    user_agent=RESEARCH_USER_AGENT, confidence=0.65, loopback=true
  }
}

local function build_request(profile, path)
  return "HEAD " .. path .. " HTTP/1.1\r\n" ..
    "Host: " .. profile.host_header .. "\r\n" ..
    "User-Agent: " .. profile.user_agent .. "\r\n" ..
    "Accept: */*\r\n" ..
    "Connection: close\r\n\r\n"
end

local function parse_header(blob)
  if not blob or #blob > MAX_HEADER_BYTES or blob:sub(-4) ~= "\r\n\r\n" then
    return nil, "stealer_route_http_header_out_of_bounds"
  end
  local framing = blob:gsub("\r\n", "")
  if framing:find("[\r\n]") then
    return nil, "stealer_route_http_header_malformed"
  end
  local lines = {}
  for line in (blob:sub(1, -5) .. "\r\n"):gmatch("(.-)\r\n") do
    if line == "" then return nil, "stealer_route_http_header_malformed" end
    lines[#lines + 1] = line
  end
  if not lines[1] or lines[1]:find("[%z\1-\8\11\12\14-\31\127]") then
    return nil, "stealer_route_http_status_malformed"
  end
  local status_text, reason = lines[1]:match(
    "^HTTP/1%.[01] ([0-9][0-9][0-9]) ?([^\r\n]*)$")
  if not status_text or not reason then return nil, "stealer_route_http_status_malformed" end
  local status = tonumber(status_text)
  local headers = {}
  for index = 2, #lines do
    local name, value = lines[index]:match("^([!#$%%&'*+%.%^_`|~%w-]+):[ \t]*(.-)[ \t]*$")
    if not name or value:find("[%z\1-\8\11\12\14-\31\127]") then
      return nil, "stealer_route_http_header_malformed"
    end
    name = name:lower()
    if headers[name] ~= nil then return nil, "stealer_route_http_duplicate_header" end
    headers[name] = value
  end
  if headers["transfer-encoding"] then
    return nil, "stealer_route_transfer_encoding_rejected"
  end
  local length_text = headers["content-length"]
  if length_text and (not length_text:match("^[0-9]+$") or #length_text > 10) then
    return nil, "stealer_route_content_length_invalid"
  end
  return {status=status, size=#blob}, nil
end

local function observe(host, port, profile, path, timeout)
  local request = build_request(profile, path)
  if #request > MAX_REQUEST_BYTES then
    return nil, "stealer_route_request_out_of_bounds", 0, 0, false
  end
  local socket = nmap.new_socket()
  socket:set_timeout(timeout)
  local connected, _ = socket:connect(host.ip, port.number, profile.tls and "ssl" or "tcp")
  if not connected then
    socket:close()
    return nil, "stealer_route_connect_failed", 0, 0, false
  end
  local sent, _ = socket:send(request)
  if not sent then
    socket:close()
    return nil, "stealer_route_send_failed", 0, 0, true
  end
  local received, header = socket:receive_buf(
    match.pattern_limit("\r\n\r\n", MAX_HEADER_BYTES), true)
  socket:close()
  if not received then
    return nil, "stealer_route_http_header_not_received", #request, 0, true
  end
  local parsed, parse_error = parse_header(header)
  if not parsed then
    return nil, parse_error, #request, header and #header or 0, true
  end
  return parsed, nil, #request, parsed.size, true
end

local function route_status(status)
  return status == 200 or status == 204 or status == 401 or
    status == 403 or status == 405
end

local function control_status(status)
  return status == 400 or status == 404 or status == 410
end

action = function(host, port)
  local mode = stdnse.get_script_args("stealer-route.mode")
  local profile_id = stdnse.get_script_args("stealer-route.profile-id")
  local acknowledgement = stdnse.get_script_args("stealer-route.acknowledge-profile")
  local expected_ip = stdnse.get_script_args("stealer-route.expected-ip")
  local profile = profile_id and PROFILES[profile_id] or nil
  if mode ~= "formbook" and mode ~= "vidar" and mode ~= "amos" then
    return stdnse.format_output(false,
      "stealer-route.mode=formbook|vidar|amos が必要です")
  end
  if not profile or acknowledgement ~= profile_id or expected_ip ~= host.ip or mode ~= profile.mode then
    return stdnse.format_output(false,
      "review済みprofile ID、同値acknowledgement、mode、数値IP pinが必要です")
  end
  if profile.loopback then
    if host.ip ~= "127.0.0.1" and host.ip ~= "::1" then
      return stdnse.format_output(false, "loopback profileはlocalhost以外へ使用できません")
    end
  elseif port.number ~= profile.port then
    return stdnse.format_output(false, "review済みprofileのportと一致しません")
  end

  local timeout = math.max(100, math.min(
    tonumber(stdnse.get_script_args("stealer-route.timeout")) or 3000, 5000))
  local responses = {}
  local sent_bytes = 0
  local response_size = 0
  local request_count = 0
  local connected = false
  local error_status = nil
  for _, path in ipairs(profile.paths) do
    local parsed, probe_error, sent_size, received_size, connection_established =
      observe(host, port, profile, path, timeout)
    connected = connected or connection_established
    sent_bytes = sent_bytes + sent_size
    response_size = response_size + received_size
    if sent_size > 0 then request_count = request_count + 1 end
    if not parsed then
      error_status = probe_error
      break
    end
    responses[#responses + 1] = parsed
  end

  local matched = false
  if not error_status and (profile.family == "formbook" or profile.family == "vidar") then
    matched = #responses == 2 and route_status(responses[1].status) and
      control_status(responses[2].status)
  elseif not error_status and profile.family == "amosstealer" then
    matched = #responses == 3 and route_status(responses[1].status) and
      route_status(responses[2].status) and control_status(responses[3].status)
  end
  local status
  if error_status then
    status = error_status
  elseif matched and profile.family == "formbook" then
    status = "formbook_reviewed_route_pair_match"
  elseif matched and profile.family == "vidar" then
    status = "vidar_reviewed_route_pair_match"
  elseif matched and profile.family == "amosstealer" then
    status = "amos_reviewed_ledger_pair_match"
  elseif profile.family == "formbook" then
    status = "formbook_reviewed_route_pair_mismatch"
  elseif profile.family == "vidar" then
    status = "vidar_reviewed_route_pair_mismatch"
  else
    status = "amos_reviewed_ledger_pair_mismatch"
  end
  local confidence = matched and profile.confidence or (connected and 0.15 or 0.0)
  return {
    family=profile.family, protocol="reviewed_http_route_observation",
    profile_id=profile_id, c2_confirmed=false, probable_c2=matched,
    confidence=confidence, status=status,
    http_status=responses[1] and responses[1].status or nil,
    primary_http_status=responses[1] and responses[1].status or nil,
    secondary_http_status=responses[2] and responses[2].status or nil,
    control_http_status=responses[#profile.paths] and responses[#profile.paths].status or nil,
    request_count=request_count, maximum_request_count=#profile.paths,
    sent_bytes=sent_bytes, response_size=response_size,
    target_connection_established=connected,
    network_contacted_by_nmap_scan=true,
    application_data_sent=sent_bytes > 0, request_body_sent=false,
    redirect_followed=false, victim_metadata_sent=false,
    synthetic_identity_sent=false, registration_attempted=false,
    task_poll_attempted=false, task_executed=false,
    payload_download_attempted=false, response_body_published=false,
    campaign_id_published=false
  }
end
