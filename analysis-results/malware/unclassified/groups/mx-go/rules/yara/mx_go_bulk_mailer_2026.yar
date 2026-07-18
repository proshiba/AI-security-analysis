rule MX_Go_Remote_Bulk_Mailer_2026 {
  meta:
    description = "MX-Go remotely controlled Japan-targeted bulk mailer"
    author = "AI-security-analysis"
    date = "2026-07-15"
    sample_sha256 = "e25053585ac5e4f411f954fe7bedc8cb62672a3f9ae96b6022a7b7116700228e"
    confidence = "high"
    false_positive = "Exact internal/research copies of the same unpublished tool"
  strings:
    $module_mail = "mx-go/internal/mail" ascii
    $module_control = "mx-go/internal/control" ascii
    $module_remote = "mx-go/internal/remote" ascii
    $mutex = "Local\\MX_Go_SingleInstance_v1" ascii
    $jp_gate = "MX_GO_SKIP_JP_CHECK" ascii
    $command_api = "/api/client_command/" ascii
    $heartbeat_api = "/api/v1/heartbeat_direct" ascii
    $recipient_url = "https://www.iainglespa.com/jp01.txt" ascii
    $control = "http://43.165.179.173:5000" ascii
  condition:
    uint16(0) == 0x5a4d and filesize > 8MB and
    all of ($module_*) and 3 of ($mutex, $jp_gate, $command_api, $heartbeat_api, $recipient_url, $control)
}