# 終端ペイロード・設定・C2解析の完了基準

## 目的

daily解析で、一次dropper、provider label、文字列走査、TCP openだけを検体単位の解析完了として扱わないための基準です。MalwareBazaar対象は全検体に`c2-analysis.json`を置き、`validate_daily_analysis.py`が検体単位の完全性と、日次バッチで安全に追加解析へ繰り越せるかを別々に検証します。

## 完了と認める結果

次のどちらかだけを完了結果とします。

1. `confirmed`: 終端payloadへ到達し、検体固有の設定または通信処理からC2を抽出し、malware protocolレベルで確認した。
2. `no_c2_capability_verified`: 終端payloadへ到達し、特徴的な全通信・設定・command処理を解析した結果、C2機能を持たないことを静的に確認した。

`unresolved`、終端未到達、暗号化設定未復元、後段取得失敗、公開sandbox未確認、TCP openのみ、provider labelのみは完了ではありません。blockerと次の最小手順を残し、深掘りqueueへ戻します。

## 必須phase

`phase_evidence`には次の10 phaseをすべて記録します。対象に存在しないphaseは`not_applicable`にできますが、存在しないと判断した根拠が必要です。`blocked`が1件でもあれば検体単位の完了にはなりません。ただし、日次で実施可能な解析を完了し、`deep_analysis`に試行済み手法、blocker、次の最小手順、優先度、queueを記録した場合は、検体を未完了のまま追加解析へ繰り越せます。

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

## 通常probeとRAT host emulator証跡

通常のC2監視は、DNS、TCP、TLS、server-first応答、またはreview済みの1回限定application probeです。対話型RATの遠隔操作channelへ登録し、bounded時間だけcommandを待つ処理は通常probeへ混在させず、`analysis-framework/common/run_defensive_rat_emulator.py`による防御的host emulatorとして分離します。AgentTeslaのFTP exfiltration sink、StealC／Lumma／Remusのtask service、loader stage配布channelはこのhost emulatorの対象ではなく、各専用probeの証跡を使います。

AsyncRAT／VenomRATでは、exact ILの`KeepAlivePacket`がactive window titleを`Ping.Message`へ格納します。host emulatorは実端末情報を送らないため`GetActiveWindowTitle`を呼ばず、合成`ClientInfo`の後に空`Message`へsanitizeした固定Ping requestを送り、`pong`／`Po_ng`またはtaskを最大1 frameだけ受信します。

host emulatorで認証済みcommandを受信した場合は、malware protocolがその時点で活動していた強い肯定証拠にできます。ただし、command本文や引数を実行せず、file／plugin／stageを取得せず、heartbeat応答、task、未知commandのいずれにも返信しません。任意操作結果のfake replyは未実装であり、result serializerが未解決の現行profileではwire応答を禁止します。公開結果でも`task_executed=false`、`real_effect_performed=false`、`synthetic_reply_sent=false`を必須とします。

短時間sessionでcommandを受信しなかったことは、C2停止、非C2、`off`、解析失敗の証拠ではありません。DNS／到達性／停止履歴と、host emulatorのsession／command fingerprintを`protocol_activity_tracking`として分離します。command未観測を7日停止判定のOFF観測へ数えません。

host emulator証跡はprotocol activityの確認を強化しますが、終端payload、設定、endpoint役割、protocol実装の静的解析を置き換えません。公開sidecarだけが存在し、終端payloadや設定との完全SHA-256／profile相関がない状態を検体単位の`confirmed`へ昇格させません。

## スクリプト化

解析契約の`automation.handlers`と`automation.tests`にはrepository内の実在fileを指定します。新しい復号、設定形式、protocol、blocker識別を手作業だけで終えず、次回同系統を自動処理できる実装とテストへ反映します。

```powershell
py -3.13 analysis-framework/common/c2_analysis_contract.py `
  --repository . `
  --case-root analysis-results/malware/<family>/versions/<version>/cases/<sha256> `
  --sha256 <sha256>
```

このcommandが非0を返すcaseは、daily完了として公開できません。

host emulator sessionを監視履歴へ反映するときは、公開要約群を`build_rat_emulation_evidence.py`で監視planへ完全bindingし、統合runnerへ次の2引数を同時に渡します。

```powershell
py -3.13 analysis-framework/common/run_c2_monitoring_pipeline.py `
  --targets analysis-results/research/c2-monitoring/YYYY-MM-DD/targets.json `
  --output-directory analysis-results/research/c2-monitoring/YYYY-MM-DD `
  --maxmind-cache-dir C:\Users\Administrator\MalwareSamples\maxmind\current `
  --rat-emulation-evidence C:\private\rat-emulation-evidence.json `
  --rat-emulation-evidence-sha256 <expected SHA-256>
```

`--rat-emulation-evidence`と`--rat-emulation-evidence-sha256`の片方だけを指定してはなりません。sidecar入力はexpected SHA-256、endpoint、family、emulator／protocol profile、registry pin、sample hash、期限、重複を再検証し、公開項目をallowlistから再構築します。

raw frame、復号command、token、鍵、合成ID、PCAP、private pathはリポジトリへ保存しません。private transcriptはhash chainと最終root SHA-256を検証し、`archive_analysis_datastore.py`を使って解析対象別のpassword `infected`のWinZip AES-256 archiveへまとめ、S3 bucket `malware-analysis-datastore-720232834682`へ保管します。公開側はsession要約、root hash、archive／manifest SHA-256等の参照だけを保持します。

## ライブ確認との分離

静的C2抽出とライブ生存確認は別の証拠です。静的抽出が成功しても、ライブ確認が未実施なら`confirmed`のdaily完了条件を満たしません。一方、hostが停止していても、検体固有configとprotocolが確認できていればC2識別自体は維持し、ライブ状態を`off`として記録します。

現在のRAT host emulatorは短時間・単一接続の手動起動runnerです。常時稼働service、無限再接続、長時間command待受、任意操作結果のfake replyは未実装であり、解析完了を理由に常駐運用を開始しません。将来の常時運用は専用VM／service account、OSレベルegress allowlist、期限付きlive lease、cooldown、log rotation、S3 upload完了確認、強制停止機構を実装・レビューし、別途明示承認を得た後に行います。
