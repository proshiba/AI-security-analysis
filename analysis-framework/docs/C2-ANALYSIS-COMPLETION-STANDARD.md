# 終端ペイロード・設定・C2解析の完了基準

## 目的

daily解析で、一次dropper、provider label、文字列走査、TCP openだけを解析完了として扱わないための基準です。MalwareBazaar対象は全検体に`c2-analysis.json`を置き、`validate_daily_analysis.py`が検体単位で検証します。

## 完了と認める結果

次のどちらかだけを完了結果とします。

1. `confirmed`: 終端payloadへ到達し、検体固有の設定または通信処理からC2を抽出し、malware protocolレベルで確認した。
2. `no_c2_capability_verified`: 終端payloadへ到達し、特徴的な全通信・設定・command処理を解析した結果、C2機能を持たないことを静的に確認した。

`unresolved`、終端未到達、暗号化設定未復元、後段取得失敗、公開sandbox未確認、TCP openのみ、provider labelのみは完了ではありません。blockerと次の最小手順を残し、深掘りqueueへ戻します。

## 必須phase

`phase_evidence`には次の10 phaseをすべて記録します。対象に存在しないphaseは`not_applicable`にできますが、存在しないと判断した根拠が必要です。`blocked`が1件でもあれば完了になりません。

| phase | 確認内容 |
|---|---|
| `root_static_analysis` | root検体の構造、entrypoint、代表関数 |
| `embedded_layer_recovery` | resource、overlay、archive、script、埋め込みPE |
| `external_payload_retrieval` | 配布URL、dead drop、追加stageの取得可否と親子関係 |
| `sandbox_artifact_review` | 完全SHA-256一致の公開sandbox、drop、config、PCAP |
| `memory_artifact_review` | memory image、process dump、復号直後pageの取得可否 |
| `terminal_payload_analysis` | 最終実行コード、family、version、機能 |
| `family_config_extraction` | 設定構造、鍵導出、endpointの役割 |
| `c2_endpoint_extraction` | 配布先、decoy、C2、exfil先の分離 |
| `c2_protocol_analysis` | check-in、frame、暗号、応答検証、command分岐 |
| `automation_and_tests` | 再利用可能なscriptとunit testへの反映 |

## C2確定条件

- endpointには値、役割、根拠を記録する。
- config decoder、process帰属付き通信、malware protocol応答を相関する。
- TCP open、HTTP status、TLS証明書、banner、JARMだけで確定しない。
- protocol確認では、実資格情報、被害端末情報、任意command、追加payload要求を送信しない。
- reviewed profileがある場合だけ、限定した合成check-inまたは応答frame検証を使う。
- 確認済みC2は全履歴監視対象へ登録し、その日の限定ライブ観測を記録する。

## スクリプト化

解析契約の`automation.handlers`と`automation.tests`にはrepository内の実在fileを指定します。新しい復号、設定形式、protocol、blocker識別を手作業だけで終えず、次回同系統を自動処理できる実装とテストへ反映します。

```powershell
py -3.13 analysis-framework/common/c2_analysis_contract.py `
  --repository . `
  --case-root analysis-results/malware/<family>/versions/<version>/cases/<sha256> `
  --sha256 <sha256>
```

このcommandが非0を返すcaseは、daily完了として公開できません。

## ライブ確認との分離

静的C2抽出とライブ生存確認は別の証拠です。静的抽出が成功しても、ライブ確認が未実施なら`confirmed`のdaily完了条件を満たしません。一方、hostが停止していても、検体固有configとprotocolが確認できていればC2識別自体は維持し、ライブ状態を`off`として記録します。
