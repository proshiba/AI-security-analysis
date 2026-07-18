import "hash"

rule ValleyRAT_JP_Malspam_202603_Exact_Hash {
  meta:
    description = "Exact outer ZIP or malicious libcef.dll from reviewed Japanese ValleyRAT campaign"
    confidence = "high"
    false_positive = "low, but hash is brittle"
  condition:
    hash.sha256(0, filesize) == "f543dcf4f178e464c7b4dc24b463272417d8ada2a7d3a832e177f37e64f10cbd" or
    hash.sha256(0, filesize) == "07ead27a736604b28876f4a0c940279983bd7076c2e1fed4039c4f0a81f3e0d5"
}

rule Suspicious_CEF_Sideload_Archive_Context {
  meta:
    description = "CEF side-load archive layout; correlate before blocking"
    confidence = "medium"
    false_positive = "high without mail and path context"
  strings:
    $dll = "libcef.dll" ascii wide nocase
    $host = "20260327003703.EXE" ascii wide nocase
  condition:
    uint32(0) == 0x04034b50 and all of them
}
