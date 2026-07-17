rule Reviewed_IndexXor_Netutils_MultiPE_Carrier
{
    meta:
        description = "Reviewed netutils side-load carrier with index-XOR payloads"
        author = "AI-security-analysis"
        date = "2026-07-16"
        false_positive = "medium; exact hash is low FP"
        sha256 = "e8a4f2026d5aac1b74acbf7033ea0ec626055d3dbf5d645c9f741a75ad17ea37"
        donut_status = "not confirmed"
    strings:
        $broker = "Microsoft\\NetTokenBroker" ascii wide
        $runtime = "runtime.tmp" ascii wide
        $heartbeat = "heartbeat.bin" ascii wide
        $killav = "HS_KILLAV_DONE" ascii wide
        $defender = "Windows Defender\\Exclusions\\Paths" ascii wide
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule Native_10FX_Terminal_RAT_Core
{
    meta:
        description = "Native 10FX RAT protocol and capability cluster"
        author = "AI-security-analysis"
        date = "2026-07-16"
        false_positive = "medium; combine with terminal hash or C2"
        sha256 = "2e12fa92aae24cf0ec9890151f28fa402324439ccd671135370cb3a2f541087e"
    strings:
        $magic = "10FX" ascii
        $screen = "START_SCREEN" ascii wide
        $preview = "SCREENSHOT_PREVIEW" ascii wide
        $browser = "BROWSER_PASSWORDS" ascii wide
        $socks = "SOCKS5_START" ascii wide
        $network = "GET_NET_CONNECTIONS" ascii wide
    condition:
        uint16(0) == 0x5a4d and $magic and 4 of ($screen, $preview, $browser, $socks, $network)
}

