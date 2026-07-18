rule LummaStealer_Unpacked_Config_2026 {
  meta:
    description = "Lumma Stealer unpacked config and credential-store strings"
    author = "AI-security-analysis"
    confidence = "medium"
    false_positive = "Go-based browser inventory or credential migration software"
  strings:
    $family1 = "LummaC2" ascii wide nocase
    $family2 = "Lumma Stealer" ascii wide nocase
    $config1 = "build_id" ascii wide nocase
    $config2 = "hwid" ascii wide nocase
    $browser1 = "Login Data" ascii wide
    $browser2 = "Local State" ascii wide
    $browser3 = "Web Data" ascii wide
    $wallet = "MetaMask" ascii wide nocase
  condition:
    uint16(0) == 0x5a4d and ((any of ($family*) and 2 of ($browser*)) or
      (all of ($config*) and 3 of ($browser*, $wallet)))
}
