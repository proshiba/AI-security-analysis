rule PureHVNC_Native_10FX_Core
{
    meta:
        description = "Native PureHVNC-like 10FX frame and capability cluster"
        author = "AI-security-analysis"
        date = "2026-07-15"
        false_positive = "medium; validate with hashes, endpoint, or side-load chain"
    strings:
        $magic = { 31 30 46 58 }
        $screen1 = "START_SCREEN" ascii wide
        $screen2 = "STOP_SCREEN" ascii wide
        $preview = "SCREENSHOT_PREVIEW" ascii wide
        $browser = "BROWSER_PASSWORDS" ascii wide
        $network = "GET_NET_CONNECTIONS" ascii wide
        $config = "config.dat" ascii wide
        $persist = "PersistDir" ascii wide
    condition:
        uint16(0) == 0x5a4d and $magic and ($preview or 2 of ($screen*)) and
        2 of ($browser, $network, $config, $persist)
}

rule PureHVNC_Netutils_Sideload_Component
{
    meta:
        description = "Reviewed PureHVNC netutils.dll side-load component"
        author = "AI-security-analysis"
        date = "2026-07-15"
        false_positive = "low for exact hash; medium for strings only"
        sha256 = "e8a4f2026d5aac1b74acbf7033ea0ec626055d3dbf5d645c9f741a75ad17ea37"
    strings:
        $net = "NetApiBufferFree" ascii
        $broker = "Microsoft\\NetTokenBroker" ascii wide
        $runtime = "runtime.tmp" ascii wide
        $heartbeat = "heartbeat.bin" ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}
