rule DonutLoader_CHRD_WAV_Carrier
{
    meta:
        description = "Reviewed CHRD/WAV resource carrier preceding Donut"
        author = "AI-security-analysis"
        date = "2026-07-15"
        false_positive = "medium; CHRD plus fake product cluster required"
        sha256 = "e55412555b4699c6d3ce2ac60df81eb1ee0d5aa412a303555c8f64037d5633d0"
    strings:
        $chrd = "CHRD" ascii
        $product = "Harbor Lantern" ascii wide
        $desc = "Lightweight calendar planner" ascii wide
    condition:
        uint16(0) == 0x5a4d and $chrd and 1 of ($product, $desc)
}

rule DonutLoader_Managed_PayloadSource
{
    meta:
        description = "Managed TripleDES/GZip loader with PayloadSource resource"
        author = "AI-security-analysis"
        date = "2026-07-15"
        false_positive = "medium"
        sha256 = "96d2f935f7973f4c31c320cd2ee2173bd6f67ac32758ecc242f928409ecf92d7"
    strings:
        $resource = "PayloadSource.zip" ascii wide
        $des = "TripleDESCryptoServiceProvider" ascii wide
        $gzip = "GZipStream" ascii wide
        $memory = "Assembly::Load" ascii wide
    condition:
        uint16(0) == 0x5a4d and $resource and 2 of ($des, $gzip, $memory)
}

rule PureRAT_Managed_44_1_Config_Profile
{
    meta:
        description = "Managed PureRAT terminal agent profile"
        author = "AI-security-analysis"
        date = "2026-07-15"
        false_positive = "medium; use terminal hash or decoded config for low FP"
        sha256 = "c1a2b48d4f639b46cf6cde8322666f0991531ef32ffe571140418ae40342ffe8"
    strings:
        $protobuf = "protobuf-net" ascii wide
        $tls = "AuthenticateAsClient" ascii wide
        $version = "4.4.1" ascii wide
        $wallet = "Wallet" ascii wide
        $telegram = "Telegram" ascii wide
    condition:
        uint16(0) == 0x5a4d and $protobuf and $tls and $version and
        1 of ($wallet, $telegram)
}
