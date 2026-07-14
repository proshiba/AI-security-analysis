rule VenomRAT_Quasar_xClient_Reviewed_2026 {
  meta:
    description = "VenomRAT/Quasar-derived managed module markers"
    author = "AI-security-analysis"
    date = "2026-07-15"
    false_positive = "Legitimate Quasar forks or security research builds"
  strings:
    $ns1 = "Quasar.Client" ascii wide
    $ns2 = "xClient.Core" ascii wide
    $cfg1 = "RECONNECTDELAY" ascii wide
    $cfg2 = "INSTALLNAME" ascii wide
    $sql = "SELECT origin_url, username_value, password_value FROM logins" ascii wide
  condition:
    uint16(0) == 0x5a4d and 3 of them
}

rule VenomRAT_Japan_TaxNotice_Artifacts_2026 {
  meta:
    description = "Reviewed Japan-observed VenomRAT Tax_Notice artifact strings"
    author = "AI-security-analysis"
    date = "2026-07-15"
    false_positive = "A benign file deliberately using the same lure naming"
  strings:
    $tax = "Tax_Notice_" ascii wide
    $runtime = "Microsoft\\Crypto\\RuntimeBroker\\RuntimeBroker.exe" ascii wide
    $consent = "ConsentPromptBehaviorAdmin" ascii wide
  condition:
    uint16(0) == 0x5a4d and $tax and 1 of ($runtime, $consent)
}
