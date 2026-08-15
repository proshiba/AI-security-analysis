local stdnse = require "stdnse"

description = [[
C2候補hostについて、Nmapがtarget解決で得たaddressだけを記録します。追加socketを開かず、
port到達性やmalware固有protocolを確認しないため、c2_confirmedは常にfalseです。
]]

author = "AI-security-analysis"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  return host and host.ip ~= nil
end

action = function(host)
  return {
    family="unclassified",
    protocol="dns_only",
    c2_confirmed=false,
    probable_c2=false,
    confidence=0.05,
    status="dns_resolved",
    resolved_ip=host.ip,
    dns_resolution_attempted=true,
    target_contact_attempted=false,
    target_connection_established=false,
    application_data_sent=false,
    sent_bytes=0,
    request_count=0,
    registration_attempted=false,
    task_poll_attempted=false,
    task_executed=false,
    payload_download_attempted=false
  }
end
