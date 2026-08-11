local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
d025 RZK carrierから復元したmanaged PureRAT 4.4.1のreview済みendpointだけを対象に、
最初からSSL/TLSで接続してleaf certificate SHA-256を照合します。plaintext prelude、
registration、task poll、application dataは送信しません。Nmap socketではTLS 1.0を
厳密に強制したことを保証しにくいため、完全一致時もPython probeよりconfidenceを
低くします。証明書不一致はbuild差分やrotationを排除できず、非C2の根拠にはしません。
]]

author = "AI-security-analysis"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "malware", "discovery"}

local PROFILE_ID = "purerat-441-d025a296-45-192-211-77-56001-direct-tls10"
local ROOT_SAMPLE_SHA256 = "d025a29613e300d7755f878eb1d23d8a8a042cb2d3eb9005d66664ab9b97c677"
local TERMINAL_SAMPLE_SHA256 = "df0359edefe34a970af39227978dbe7f1caa09caf98a2c6db53f49187ec25dd7"
local REVIEWED_HOST = "45.192.211.77"
local REVIEWED_PORT = 56001
local EXPECTED_CERTIFICATE_SHA256 = "b3ae061b0b14a89d5134c279775b8f77a42214323c6bddab07f4d81ca2fc5c57"

portrule = function(_, port)
  return port.protocol == "tcp" and port.state == "open" and port.number == REVIEWED_PORT
end

local function base_result(host, port)
  local endpoint_exact = host.ip == REVIEWED_HOST and port.number == REVIEWED_PORT
  return {
    family="purehvnc",
    variant="managed_purerat_4_4_1_direct_tls",
    profile_id=PROFILE_ID,
    root_sample_sha256=ROOT_SAMPLE_SHA256,
    terminal_sample_sha256=TERMINAL_SAMPLE_SHA256,
    protocol="direct_tls_certificate_only",
    application_framing="le32_gzip_protobuf_net_not_sent",
    reviewed_host=REVIEWED_HOST,
    reviewed_port=REVIEWED_PORT,
    target_endpoint_exact_match=endpoint_exact,
    tls_version_expected="TLSv1.0",
    tls_version_enforced_by_nse=false,
    plaintext_prelude_sent=false,
    application_data_sent=false,
    victim_metadata_sent=false,
    registration_attempted=false,
    task_poll_attempted=false,
    task_executed=false,
    operation_command_sent=false,
    certificate_mismatch_excludes_c2=false,
    certificate_mismatch_excludes_exact_build_endpoint=true,
    certificate_mismatch_excludes_family_c2=false,
    network_contacted_by_nmap_scan=true
  }
end

action = function(host, port)
  local result = base_result(host, port)
  if not result.target_endpoint_exact_match then
    result.status = "reviewed_endpoint_mismatch"
    result.c2_confirmed = false
    result.family_c2_candidate = nil
    result.exact_profile_match = false
    result.confidence = 0.0
    result.target_contact_attempted_by_script = false
    return result
  end

  local socket = nmap.new_socket()
  socket:set_timeout(math.max(100, math.min(tonumber(stdnse.get_script_args("purerat-direct-tls.timeout")) or 3000, 5000)))
  local ok, err = socket:connect(host.ip, port.number, "ssl")
  if not ok then
    socket:close()
    result.status = "purerat_direct_tls_handshake_failed"
    result.c2_confirmed = false
    result.family_c2_candidate = nil
    result.exact_profile_match = false
    result.confidence = 0.20
    result.target_contact_attempted_by_script = true
    result.error = err
    return result
  end

  local cert = socket:get_ssl_certificate()
  socket:close()
  local observed = cert and stdnse.tohex(cert:digest("sha256")) or nil
  local exact = observed and observed:lower() == EXPECTED_CERTIFICATE_SHA256 or false
  result.status = exact and "purerat_direct_tls_certificate_match" or "purerat_direct_tls_certificate_mismatch_inconclusive"
  result.c2_confirmed = exact
  result.family_c2_candidate = exact and true or nil
  result.exact_profile_match = exact
  result.confidence = exact and 0.92 or 0.35
  result.target_contact_attempted_by_script = true
  result.certificate_sha256 = observed
  result.expected_certificate_sha256 = EXPECTED_CERTIFICATE_SHA256
  result.certificate_exact_match = exact
  result.certificate_state = exact and "exact_match" or "mismatch_inconclusive"
  return result
end
