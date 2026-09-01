# ClickFix配信ロジック

## 配信フロー

```mermaid
flowchart LR
  D1["P1 ClickFix誘導"] -. "command未取得" .-> D2["P2 配布URL"]
  D2 --> D3["P3 password付きarchive"]
  D3 --> D4["P4 payload hash確認"]
  D4 -. "実行しない" .-> D5["P5 静的解析"]
```

## 実行境界

```mermaid
flowchart TD
  E1["利用者操作<br/>未観測"] -.-> E2["WMIsave.exe起動候補"]
  E2 -. "禁止境界" .-> E3["process・永続化・通信"]
  E2 --> E4["hash／PE／string／Ghidra静的解析"]
  E3 -. "実行証跡ではない" .-> E4
```

## 成果物の分離

```mermaid
flowchart LR
  M1["ClickFix case"] --> M2["配布URL・archive・infra・triage"]
  M1 --> M3["canonical malware case"]
  M3 --> M4["packing・process候補・persistence"]
  M3 --> M5["API解決・clipboard置換"]
```

実線は確認済み関係、点線は未観測または禁止した実行境界を表す。ClickFix側では配布関係だけを
正本とし、binary機能を複製しない。生commandが取得されていないため、ClickFixで典型的な
`mshta`、`powershell`、`curl`等を本caseの初段commandとして断定しない。
