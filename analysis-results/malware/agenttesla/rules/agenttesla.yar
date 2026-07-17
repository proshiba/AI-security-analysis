rule AgentTesla_Obfuscated_Script_Loaders_Jul2026
{
    meta:
        description = "AgentTesla script-loader clusters observed in the reviewed July 2026 set"
        author = "AI-security-analysis"
        date = "2026-07-13"
        confidence = "medium"
        false_positive = "Obfuscated enterprise scripts using in-memory .NET; validate origin and behavior"
    strings:
        $download = "DownloadData" ascii wide nocase
        $appdomain = "AppDomain" ascii wide
        $load = ".Load(" ascii wide
        $marker1 = "IN-" ascii wide
        $marker2 = "-in1" ascii wide
        $b64 = "FromBase64String" ascii wide
        $js1 = "fromCharCode" ascii wide
        $js2 = "eval(" ascii wide
        $entry = "OtnmpxnddVnptbN" ascii wide
    condition:
        filesize < 8MB and
        (($download and $appdomain and $load and 1 of ($marker*)) or
         ($b64 and $entry) or
         ($js1 and $js2 and 1 of ($download, $appdomain, $b64)))
}
