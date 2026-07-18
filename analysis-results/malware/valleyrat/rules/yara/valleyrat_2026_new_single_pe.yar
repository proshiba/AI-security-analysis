rule Suspicious_N520_Managed_Backdoor_2026_07
{
    meta:
        description = "Detects the managed N520-style backdoor submitted with ValleyRAT/SilverFox labels"
        author = "AI-security-analysis"
        date = "2026-07-14"
        confidence = "medium"
        sha256 = "d11e793159f0da3c88a9ecebb8e5df88919843a1eeaaf71117377db58224a1ae"
        note = "Campaign/family attribution remains under review"

    strings:
        $env1 = "N_SERVER_IP" wide
        $env2 = "N_MACHINE_BINDING" wide
        $env3 = "N_STATION_ID" wide
        $cloud = "I1Y9qQuau1uAmjUUc4oEGOVY3HMLfwFfs3XVQOoWnunKFCMmvxtETQ8ryexTkMRVXUIsq6zey00Wx1z8vuOnJA==" wide
        $socks = "socks5" wide nocase
        $handshake_crc = { E6 63 4B 62 05 53 20 00 43 00 52 00 43 00 }

    condition:
        uint16(0) == 0x5A4D and filesize < 500KB and
        ($cloud or (2 of ($env*) and ($socks or $handshake_crc)))
}
