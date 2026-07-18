rule RemusStealer_Unpacked_Static_2026 {
  meta:
    description = "Remus Stealer unpacked family and collection strings"
    author = "AI-security-analysis"
    confidence = "medium"
    false_positive = "Go credential inventory, browser backup, or wallet utilities"
  strings:
    $family1 = "RemusStealer" ascii wide nocase
    $family2 = "Remus Stealer" ascii wide nocase
    $browser1 = "Login Data" ascii wide
    $browser2 = "Local State" ascii wide
    $browser3 = "Cookies" ascii wide
    $wallet1 = "wallet.dat" ascii wide nocase
    $wallet2 = "Electrum" ascii wide nocase
    $wallet3 = "MetaMask" ascii wide nocase
  condition:
    uint16(0) == 0x5a4d and (any of ($family*) and 3 of ($browser*, $wallet*))
}
