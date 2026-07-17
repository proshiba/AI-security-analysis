rule Vidar_Unpacked_Config_Artifacts_2026 {
  meta:
    description = "Vidar unpacked collection and staging artifact strings"
    author = "AI-security-analysis"
    confidence = "medium"
    false_positive = "browser backup, forensic, or credential migration utilities"
  strings:
    $a = "information.txt" ascii wide nocase
    $b = "passwords.txt" ascii wide nocase
    $c = "Autofill" ascii wide
    $d = "wallet.dat" ascii wide
    $e = "sqlite3.dll" ascii wide nocase
    $f = "freebl3.dll" ascii wide nocase
    $g = "nss3.dll" ascii wide nocase
  condition:
    uint16(0) == 0x5a4d and 4 of them
}
