local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
e554 PureRAT/PureHVNCケースのreview済み3 endpointに対する旧互換仮説です。
4-byte prelude 04000000を送信後、同じsocketをTLSへ昇格して設定内証明書の
SHA-256と照合します。ただしe554の保存済み静的証拠はendpointと証明書を確定する
一方、このpreludeを当該buildのwire実装として証明していません。そのため完全一致時も
probable判定に限定し、c2_confirmedは常にfalseです。

profile ID、同値acknowledgement、review済みhost/port、期待証明書が一致しない場合は
socketを開きません。Nmap socket APIではTLS 1.2だけを厳密に強制したことを検証できず、
結果へtls_version_enforced_by_nse=falseを明示します。
]]

author = "AI-security-analysis"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "malware", "discovery"}

local REVIEWED_HOST = "tirakian.com"
local EXPECTED_CERTIFICATE_SHA256 =
  "67260a713ab105197098882f6d126f89fe4f48df8013f8bba1d2c9307b17410b"
local PROFILES = {
  ["purerat-441-e5541255-tirakian-56001"] = {port=56001},
  ["purerat-441-e5541255-tirakian-56002"] = {port=56002},
  ["purerat-441-e5541255-tirakian-56003"] = {port=56003}
}

portrule = function(_, port)
  if port.protocol ~= "tcp" or port.state ~= "open" then return false end
  return port.number == 56001 or port.number == 56002 or port.number == 56003
end

local function base_result(profile_id)
  return {
    family="purehvnc",
    variant="managed_purerat_4_4_1_legacy_prelude_hypothesis",
    profile_id=profile_id,
    protocol="purerat_legacy_prelude_hypothesis",
    compatibility_hypothesis=true,
    c2_confirmed=false,
    probable_c2=false,
    confidence=0.0,
    tls_version_expected="TLSv1.2",
    tls_version_enforced_by_nse=false,
    certificate_mismatch_excludes_c2=false,
    certificate_mismatch_excludes_family_c2=false,
    observation_excludes_purerat=false,
    victim_metadata_sent=false,
    registration_attempted=false,
    task_poll_attempted=false,
    task_executed=false,
    payload_download_attempted=false,
    application_data_sent=false,
    plaintext_prelude_sent=false,
    sent_bytes=0,
    received_bytes=0,
    request_count=0,
    target_contact_attempted_by_script=false
  }
end

action = function(host, port)
  local profile_id = stdnse.get_script_args("purerat.profile-id")
  local acknowledgement = stdnse.get_script_args("purerat.acknowledge-profile")
  local expected_host = stdnse.get_script_args("purerat.expected-host")
  local expected_certificate = stdnse.get_script_args("purerat.expected-cert")
  local profile = profile_id and PROFILES[profile_id] or nil
  local result = base_result(profile_id)
  local target_name = host.targetname or host.name
  if not profile or acknowledgement ~= profile_id or
     expected_host ~= REVIEWED_HOST or target_name ~= REVIEWED_HOST or
     expected_certificate ~= EXPECTED_CERTIFICATE_SHA256 or
     port.number ~= profile.port then
    result.status = "purerat_legacy_prelude_reviewed_profile_gate_failed"
    result.profile_acknowledged = false
    return result
  end
  result.profile_acknowledged = true
  result.target_endpoint_exact_match = true

  local socket = nmap.new_socket()
  socket:set_timeout(math.max(100, math.min(
    tonumber(stdnse.get_script_args("purerat.timeout")) or 3000, 5000)))
  result.target_contact_attempted_by_script = true
  local connected, connect_error = socket:connect(host.ip, port.number, "tcp")
  if not connected then
    socket:close()
    result.status = "purerat_legacy_prelude_tcp_connect_failed"
    result.error = connect_error
    return result
  end
  local sent, send_error = socket:send(string.char(4, 0, 0, 0))
  if not sent then
    socket:close()
    result.status = "purerat_legacy_prelude_send_failed"
    result.error = send_error
    return result
  end
  result.application_data_sent = true
  result.plaintext_prelude_sent = true
  result.sent_bytes = 4
  result.request_count = 1
  local tls_ok, tls_error = socket:reconnect_ssl()
  if not tls_ok then
    socket:close()
    result.status = "purerat_legacy_prelude_tls_failed"
    result.error = tls_error
    return result
  end
  local certificate = socket:get_ssl_certificate()
  socket:close()
  local observed = certificate and stdnse.tohex(certificate:digest("sha256")) or nil
  local exact = observed and observed:lower() == EXPECTED_CERTIFICATE_SHA256 or false
  result.certificate_sha256 = observed
  result.certificate_exact_match = exact
  result.status = exact and
    "purerat_legacy_prelude_hypothesis_certificate_match_tls_version_unverified" or
    "purerat_legacy_prelude_certificate_mismatch_inconclusive"
  result.probable_c2 = exact
  result.c2_confirmed = false
  result.confidence = exact and 0.60 or 0.0
  return result
end
