local base64 = require "base64"
local http = require "http"
local stdnse = require "stdnse"

description = [[
StealC v2、Lumma v6、Remus Stealerのレビュー済み最小HTTP登録形式を1要求だけ送信します。
task取得やpayload追跡は行いません。StealCはRC4応答内のaccess_token形式まで検証し、
Lumma/Remusは登録応答のHTTP・本文構造を中程度の根拠として報告します。
]]

author = "AI-security-analysis"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "malware", "discovery"}

portrule = function(_, port)
  return port.protocol == "tcp" and port.state == "open"
end

local function urlencode(value)
  return (value:gsub("([^%w%-_%.~])", function(char)
    return string.format("%%%02X", string.byte(char))
  end))
end

local function rc4(data, key)
  if #key == 0 then return nil end
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
    local value = data:byte(offset) ~ state[(state[left] + state[right]) & 0xff]
    output[offset] = string.char(value)
  end
  return table.concat(output)
end

local function options(host_header, content_type, user_agent)
  return {
    no_cache=true,
    timeout=math.max(100, math.min(tonumber(stdnse.get_script_args("stealer.timeout")) or 3000, 5000)),
    header={
      ["Host"]=host_header,
      ["Content-Type"]=content_type,
      ["User-Agent"]=user_agent,
      ["Connection"]="close"
    }
  }
end

local function stealc(host, port)
  local build = stdnse.get_script_args("stealer.build")
  local encoded_key = stdnse.get_script_args("stealer.key-base64")
  if not build or not encoded_key then
    return stdnse.format_output(false, "StealCにはstealer.buildとstealer.key-base64が必要です")
  end
  local key_ok, key = pcall(base64.dec, encoded_key)
  if not key_ok or not key or #key < 8 or #key > 64 or #build > 64 then
    return stdnse.format_output(false, "StealC profile引数が安全境界外です")
  end
  local plain = string.format('{"build":"%s","hwid":"00000000-0000-4000-8000-000000000000","type":"create"}', build)
  local body = base64.enc(rc4(plain, key))
  local host_header = stdnse.get_script_args("stealer.host") or host.targetname or host.ip
  local response = http.post(host, port, "/", options(host_header, "application/json",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), nil, body)
  local decoded
  if response and response.body then
    local b_ok, encrypted = pcall(base64.dec, response.body:gsub("%s", ""))
    if b_ok and encrypted then decoded = rc4(encrypted, key) end
  end
  local token = decoded and decoded:match('"access_token"%s*:%s*"([0-9a-fA-F]+)"') or nil
  local matched = response and (response.status == 200 or response.status == 201) and token and #token >= 64 and #token <= 128
  return {
    family="stealc", protocol="http_rc4_registration", c2_confirmed=matched and true or false,
    confidence=matched and 0.90 or 0.45,
    status=matched and "stealc_registration_token_match" or "stealc_registration_mismatch",
    http_status=response and response.status or nil, response_size=response and response.body and #response.body or 0,
    access_token_published=false, synthetic_identity_sent=true,
    task_poll_attempted=false, payload_download_attempted=false
  }
end

local function lumma(host, port)
  local uid = stdnse.get_script_args("stealer.uid")
  if not uid or #uid < 32 or #uid > 64 or uid:find("[^0-9a-fA-F]") then
    return stdnse.format_output(false, "Lummaには32〜64桁hexのstealer.uidが必要です")
  end
  local cid = stdnse.get_script_args("stealer.cid") or ""
  local body = "uid=" .. urlencode(uid) .. "&cid=" .. urlencode(cid)
  local host_header = stdnse.get_script_args("stealer.host") or host.targetname or host.ip
  local response = http.post(host, port, "/", options(host_header,
    "application/x-www-form-urlencoded",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/109.0.5414.120"), nil, body)
  local content_type = response and response.header and response.header["content-type"] or ""
  local prefix = response and response.body and response.body:sub(1,64):lower() or ""
  local matched = response and (response.status == 200 or response.status == 201) and
    response.body and #response.body > 0 and not prefix:match("^%s*<") and
    (content_type == "" or content_type:match("application/json") or
     content_type:match("application/octet%-stream") or content_type:match("text/plain"))
  return {
    family="lummastealer", protocol="http_uid_registration", c2_confirmed=false,
    probable_c2=matched and true or false, confidence=matched and 0.78 or 0.35,
    status=matched and "lumma_registration_shape_match" or "lumma_registration_mismatch",
    http_status=response and response.status or nil, response_size=response and response.body and #response.body or 0,
    synthetic_identity_sent=true, task_poll_attempted=false
  }
end

local function remus(host, port)
  local tag = stdnse.get_script_args("stealer.tag")
  local exp = stdnse.get_script_args("stealer.exp")
  if not tag or #tag ~= 32 or tag:find("[^0-9a-fA-F]") or not exp or exp:find("[^0-9]") then
    return stdnse.format_output(false, "Remusには32桁hexのstealer.tagと数値stealer.expが必要です")
  end
  local body = "tag=" .. tag .. "&exp=" .. exp .. "&hwid=00000000000040008000000000000000"
  local host_header = stdnse.get_script_args("stealer.host") or "microsoft.com"
  local opts = options(host_header, "application/x-www-form-urlencoded",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/117.0.0.0")
  opts.header["Cache-Control"] = "no-cache"
  opts.header["Pragma"] = "no-cache"
  local response = http.post(host, port, "/", opts, nil, body)
  local matched = response and response.status == 201 and response.body and #response.body > 40
  return {
    family="remusstealer", protocol="http_encrypted_registration", c2_confirmed=false,
    probable_c2=matched and true or false, confidence=matched and 0.78 or 0.35,
    status=matched and "remus_registration_envelope_match" or "remus_registration_mismatch",
    http_status=response and response.status or nil, response_size=response and response.body and #response.body or 0,
    synthetic_identity_sent=true, access_token_published=false,
    task_poll_attempted=false, payload_download_attempted=false
  }
end

action = function(host, port)
  local family = stdnse.get_script_args("stealer.family")
  if family == "stealc" then return stealc(host, port) end
  if family == "lumma" then return lumma(host, port) end
  if family == "remus" then return remus(host, port) end
  return stdnse.format_output(false, "--script-args stealer.family=stealc|lumma|remus が必要です")
end
