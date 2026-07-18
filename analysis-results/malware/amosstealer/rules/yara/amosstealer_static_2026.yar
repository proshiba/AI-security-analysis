rule AMOS_MachO_Collection_Strings_2026 {
  meta:
    description = "Atomic macOS Stealer collection and exfiltration string combination"
    author = "AI-security-analysis"
    confidence = "medium"
    false_positive = "macOS browser migration, backup, or wallet-management applications"
  strings:
    $keychain = "keychain" ascii nocase
    $login = "Login Data" ascii
    $cookies = "Cookies" ascii
    $ledger = "/ledger/" ascii
    $electrum = "Electrum" ascii nocase
    $exodus = "Exodus" ascii nocase
    $history = "History" ascii
  condition:
    uint32(0) == 0xfeedfacf and 5 of them
}

rule AMOS_AppleScript_Delivery_2026 {
  meta:
    description = "AMOS-style AppleScript collection and upload chain"
    author = "AI-security-analysis"
    confidence = "medium"
    false_positive = "administrative AppleScript that combines credential prompts and upload"
  strings:
    $a = "tell application \"System Events\"" ascii nocase
    $b = "security find-generic-password" ascii nocase
    $c = "display dialog" ascii nocase
    $d = "Login Data" ascii
    $e = "/ledger/" ascii
    $f = "curl" ascii nocase
  condition:
    4 of them
}
