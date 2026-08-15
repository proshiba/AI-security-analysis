local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
PureRAT/PureHVNCの4-byte prelude 04000000を送信し、同じsocketをTLS 1.2へ昇格します。
期待証明書SHA-256が指定された場合は一致を強い根拠にします。不一致だけでは、改変build、
fork、証明書rotationを除外できないため非C2とは判定しません。

confidenceは analysis-results/research/c2-protocol-profiles/2026-08-05-purerat/README.md
の判定表に合わせています。pin一致=0.95、pinなし・不一致=0.60、prelude後にTLSが
成立しない=0.25(TCP到達のみ)。値を変える場合は判定表と同時に更新してください。
]]

author = "AI-security-analysis"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "malware", "discovery"}

-- 既定では走査した開放TCP port すべてに4 byteを送る。対象を絞りたい場合は
-- nmap の -p か、purerat.ports に "56001,56002,56003" のような一覧を渡す。
portrule = function(_, port)
  if not (port.protocol == "tcp" and port.state == "open") then return false end
  local allowed = stdnse.get_script_args("purerat.ports")
  if not allowed then return true end
  for value in tostring(allowed):gmatch("[^,%s]+") do
    if tonumber(value) == port.number then return true end
  end
  return false
end

action = function(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(math.max(100, math.min(tonumber(stdnse.get_script_args("purerat.timeout")) or 3000, 5000)))
  local ok, err = socket:connect(host.ip, port.number, "tcp")
  if not ok then socket:close(); return stdnse.format_output(false, err) end
  local sent, send_err = socket:send(string.char(4, 0, 0, 0))
  if not sent then socket:close(); return stdnse.format_output(false, send_err) end
  local tls_ok, tls_err = socket:reconnect_ssl()
  if not tls_ok then socket:close(); return {
    family="purehvnc", variant="managed_purerat", c2_confirmed=false,
    -- TCPは開いていたがprotocol固有の根拠は得られていない。判定表の
    -- 「TCP接続だけ」と同じ上限に揃える。
    confidence=0.25, status="purerat_prelude_tls_failed", error=tls_err,
    certificate_mismatch_excludes_c2=false, observation_excludes_purerat=false}
  end
  local cert = socket:get_ssl_certificate()
  socket:close()
  local observed = cert and stdnse.tohex(cert:digest("sha256")) or nil
  local expected = stdnse.get_script_args("purerat.expected-cert")
  local exact = expected and observed and expected:lower() == observed:lower() or false
  local certificate_exact_match = nil
  if expected then certificate_exact_match = exact end
  return {
    family="purehvnc", variant="managed_purerat", protocol="purerat_prelude_tls12",
    -- 判定表: pin完全一致=0.95 / pinなし・不一致=最大0.60
    c2_confirmed=exact, confidence=exact and 0.95 or 0.60,
    status=exact and "purerat_prelude_tls_certificate_match" or "purerat_prelude_tls_observed",
    prelude_hex="04000000", certificate_sha256=observed,
    certificate_exact_match=certificate_exact_match,
    certificate_mismatch_excludes_c2=false, observation_excludes_purerat=false,
    victim_metadata_sent=false,
    registration_attempted=false, task_poll_attempted=false
  }
end
