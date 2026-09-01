# ClickFix配信チェーン

```mermaid
flowchart LR
  A["ClickFix誘導<br/>内容未取得"] -. "生command未確認" .-> B["fingerprint-verification.info"]
  B --> C["WMIsave.7z<br/>password 002700"]
  C --> D["WMIsave.exe"]
  D -. "未実行" .-> E["正規malware caseで静的解析"]
```

| phase | 証跡 | 状態 |
|---|---|---|
| 誘導 | ClickFix由来との提供情報 | provider context。画面・commandは未取得 |
| 配布 | Zone.Identifierの完全URL | confirmed |
| archive | `WMIsave.7z`、password `002700` | confirmed、未実行 |
| payload | `WMIsave.exe`完全SHA-256 | confirmed、未実行 |
| 後段動作 | canonical malware case | 静的解析。動的観測ではない |
