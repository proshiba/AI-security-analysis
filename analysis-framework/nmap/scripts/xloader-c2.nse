local stdnse = require "stdnse"

description = [[
XLoader／Formbook系候補のNmap TCP到達性を、protocol確定と分離して記録します。
NSEへ検体固有の多層暗号鍵を持ち込まず、HTTP登録、candidate spray、task取得、payload取得を
一切行いません。このmodeのc2_confirmedは常にfalseで、能動check-inの代替ではありません。
]]

author = "AI-security-analysis"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "malware", "discovery"}

portrule = function(_, port)
  return port.protocol == "tcp" and port.state == "open"
end

action = function(_, port)
  local mode = stdnse.get_script_args("xloader.mode")
  local acknowledgement = stdnse.get_script_args("xloader.acknowledge-no-protocol-check")
  if mode ~= "transport-only" or acknowledgement ~= "true" then
    return stdnse.format_output(false,
      "xloader.mode=transport-onlyとxloader.acknowledge-no-protocol-check=trueが必要です")
  end
  return {
    family="xloader", aliases="formbook_loader,guloader_xloader_payload",
    protocol="transport_only_capability", c2_confirmed=false,
    probable_c2=false, confidence=0.15, status="xloader_tcp_open_only",
    port_number=port.number, transport_reachable=true,
    sample_executed=false, network_contacted_by_nmap_scan=true,
    exact_private_profile_loaded=false, protocol_request_built=false,
    application_data_sent=false, sent_bytes=0, request_count=0,
    candidate_count_contacted=0, candidate_spray_attempted=false,
    registration_attempted=false, task_poll_attempted=false,
    task_executed=false, payload_download_attempted=false,
    note="TCP openだけではXLoader C2を確認できません。検体固有private profileによるPython検証が必要です"
  }
end
