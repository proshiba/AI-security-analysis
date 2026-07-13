rule RemcosRAT_Native_And_Script_Artifacts_Jul2026
{
    meta:
        description = "Remcos runtime/configuration or reviewed staged-loader combinations"
        author = "AI-security-analysis"
        date = "2026-07-13"
        confidence = "medium-high"
        false_positive = "Legitimate Remcos installations exist; require authorization and telemetry context"
    strings:
        $remcos1 = "Remcos Agent" ascii wide nocase
        $remcos2 = "Rmc-" ascii wide
        $mic = "MicRecords" ascii wide
        $keylog = "logs.dat" ascii wide
        $geo = "pro.ip-api.com/line/?key=" ascii wide
        $script1 = "ActiveXObject" ascii wide
        $script2 = "WScript.ScriptFullName" ascii wide
        $stage1 = "MSI_PRO.png" ascii wide nocase
        $stage2 = "DownloadData" ascii wide nocase
    condition:
        filesize < 20MB and
        ((uint16(0) == 0x5a4d and 2 of ($remcos*, $mic, $keylog, $geo)) or
         (2 of ($script*, $stage*) and 1 of ($remcos*, $mic, $keylog)))
}
