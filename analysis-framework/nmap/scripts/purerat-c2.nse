local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
PureRAT/PureHVNCの4-byte prelude 04000000を送信し、同じsocketをTLS 1.2へ昇格します。
期待証明書SHA-256が指定された場合は一致を強い根拠にします。不一致だけでは、改変build、
fork、証明書rotationを除外できないため非C2とは判定しません。
]]

author = "AI-security-analysis"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "malware", "discovery"}

portrule = function(_, port)
  return port.protocol == "tcp" and port.state == "open"
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
    confidence=0.35, status="purerat_prelude_tls_failed", error=tls_err}
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
    c2_confirmed=exact, confidence=exact and 0.98 or 0.80,
    status=exact and "purerat_prelude_tls_certificate_match" or "purerat_prelude_tls_observed",
    prelude_hex="04000000", certificate_sha256=observed,
    certificate_exact_match=certificate_exact_match,
    certificate_mismatch_excludes_c2=false, victim_metadata_sent=false,
    registration_attempted=false, task_poll_attempted=false
  }
end
