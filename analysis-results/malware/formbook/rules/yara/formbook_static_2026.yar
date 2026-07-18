rule Formbook_Unpacked_Static_2026 {
  meta:
    description = "Formbook/XLoader unpacked payload string combination"
    author = "AI-security-analysis"
    confidence = "medium"
    false_positive = "debuggers, credential migration, or software using the same injection APIs"
  strings:
    $family1 = "FormBook" ascii wide nocase
    $family2 = "XLoader" ascii wide nocase
    $inject1 = "NtSetContextThread" ascii
    $inject2 = "GetThreadContext" ascii
    $inject3 = "WriteProcessMemory" ascii
    $cred1 = "Login Data" ascii wide
    $cred2 = "Thunderbird" ascii wide
    $cred3 = "Foxmail" ascii wide
  condition:
    uint16(0) == 0x5a4d and (any of ($family*) or (2 of ($inject*) and 2 of ($cred*)))
}
