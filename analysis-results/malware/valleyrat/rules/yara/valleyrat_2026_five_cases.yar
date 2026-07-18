import "pe"

rule ValleyRAT_VvaS_Xor20_Config_2026_07 {
  meta:
    description = "Decoded ValleyRAT vvaS shellcode config used by July 2026 bundle"
    confidence = "high"
  strings:
    $marker = "odaktomk" ascii
    $c2 = "134.122.128.66" ascii
    $p1 = { 0A 1A 00 00 }
    $p2 = { B8 22 00 00 }
  condition:
    uint16(0) != 0x5a4d and all of them
}

rule ValleyRAT_Direct_Task_Campaign_EAB4918E {
  meta:
    description = "ValleyRAT direct signed PE campaign strings"
    confidence = "medium"
  strings:
    $task = "WinUpdateService" ascii wide
    $schtasks = "schtasks.exe" ascii wide
    $name = "Open the latest report on the computer.exe" ascii wide
  condition:
    uint16(0) == 0x5a4d and 2 of them
}

rule ValleyRAT_MSI_34UXpv_Campaign_2026_07 {
  meta:
    description = "ValleyRAT MSI staged campaign artifacts"
    confidence = "medium"
  strings:
    $host = "34UXpv.exe" ascii wide
    $dll = "XPSPLOG.dll" ascii wide
    $domain = "tlhcoz.net" ascii wide
    $stage = "26nn.oss-cn-hangzhou.aliyuncs.com" ascii wide
  condition:
    2 of them
}
