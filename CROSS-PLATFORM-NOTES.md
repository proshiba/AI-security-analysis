# クロスプラットフォーム実行メモ

## 対応する入口

| ファイル | 用途 |
|---|---|
| `analysis-framework/invoke_analysis.py` | 標準one-shotおよび旧ValleyRATフロー |
| `analysis-framework/invoke_family_batch.py` | AgentTesla／RemcosRATの一括静的解析 |
| `analysis-framework/common/import_ghidra_project.py` | Ghidra headless import |
| `analysis-framework/tests/verify_known_families.py` | 既知AgentTesla／RemcosRAT回帰確認 |
| `analysis-framework/malware/valleyrat/tests/verify_known_samples.py` | 既知ValleyRAT回帰確認 |

Python entrypointがWindows、Linux、REMnuxで同じCLIを提供します。Windowsの`analyzeHeadless.bat`／`.cmd`だけは`cmd.exe`境界です。POSIX版と通常の実行fileは`shell=False`の引数listで起動します。

## Pythonの選択

`--python`には実Python interpreterを指定し、`.bat`／`.cmd`は拒否します。省略時は次の順で選択します。

1. Windows: `analysis-framework/.venv/Scripts/python.exe`
2. Linux／REMnux: 実行権限を持つ`analysis-framework/.venv/bin/python`
3. entrypointを起動した`sys.executable`

Python 3.11以上が必要です。各子stageには親process側timeoutを適用し、既定は1,800秒、VT取得とC2 probeは120秒です。

## Windowsでの実行

```powershell
cd <repo-root>\analysis-framework
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe .\invoke_analysis.py `
  --sample C:\malware-lab\samples\sample.zip `
  --output-directory C:\malware-lab\out
```

## Linuxでの実行

```bash
cd <repo-root>/analysis-framework
python3.11 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python invoke_analysis.py \
  --sample /srv/malware-lab/samples/sample.zip \
  --output-directory /srv/malware-lab/out
```

## REMnuxでの実行

REMnuxでもsystem Pythonへ直接packageを追加せず、専用venvを使います。

```bash
cd <repo-root>/analysis-framework
python3.11 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
GHIDRA_HOME=/opt/ghidra \
  .venv/bin/python common/import_ghidra_project.py \
  --payload-directory /srv/malware-lab/payload \
  --project-directory /srv/malware-lab/ghidra-projects \
  --project-name sample-static \
  --target loader.dll
```

`support/analyzeHeadless`には実行権限が必要です。processor moduleとGhidra versionもWindows側と揃えます。

## `Invoke-Analysis.ps1`との引数対応

| PowerShell | Python |
|---|---|
| `-Sample` | `--sample` |
| `-OutputDirectory` | `--output-directory` |
| `-ProfilePath` | `--profile-path` |
| `-NetworkEvidence` | `--network-evidence` |
| `-MalwareType` | `--malware-type` |
| `-VirusTotalApiKey` | `VT_API_KEY`を設定し、`--fetch-virus-total-evidence`を指定する。key値はCLI引数へ置かない |
| `-AllowLiveC2Check` | `--allow-live-c2-check` |
| `-CollectJarm` | `--collect-jarm --jarm-script <path>`。`--allow-live-c2-check`との併用必須 |
| `-ArchiveMode` | `--archive-mode {auto,raw,malwarebazaar}` |
| `-AssessmentOnly` | `--assessment-only` |
| `-LegacyValleyWorkflow` | `--legacy-valley-workflow` |
| `-Python` | `--python` |

通常は`common/analyze_sample.py`へ委譲します。profile、network evidence、live C2、旧フロー、または明示VT取得がある場合だけ旧ValleyRAT分岐を使います。標準one-shotと旧フローの両方で、出力の親componentを含むlexical pathにあるsymlink／junction／reparse pointを子stage開始前後に拒否します。標準one-shotの既存treeは100,000 entry上限で再帰走査し、内部のsymlink／reparse point、hardlink、特殊fileも子stage前に拒否します。旧フローの既存出力は完全に空であることも必須です。

## 外部通信と秘密情報

既定では外部通信を行いません。`VT_API_KEY`が環境にあるだけでは接続しません。`--fetch-virus-total-evidence`を明示した場合だけ、先頭末尾に空白のないkeyを使います。key値を受け取るCLI optionは公開しません。

通常stageから`VT_API_KEY`、`TRIAGE_API_KEY`、`MAXMIND_LICENSE_KEY`、`GITHUB_TOKEN`、`GH_TOKEN`、`AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY`、`AWS_SESSION_TOKEN`を既定除去し、専用stageへ明示overlayした値だけを渡します。

live C2は`--allow-live-c2-check`とreview済みprofileの両方が必要です。target件数、port、protocol、送信hex、期待stage sizeを制限します。JARM収集には`--collect-jarm`に加えて、公式Salesforce JARMの`jarm.py`を`--jarm-script`で明示します。scriptは16 MiB以下の通常単一link fileに限定し、親pathを含むsymlink／reparse pointを拒否します。Windows固定pathへのfallbackは行わず、REMnux／Linux／別userのWindowsでも未指定ならfail-closedにします。

## Family batchの入力とidentity認証

case名はlowercase 64桁SHA-256、外装名は`<case-sha256>.zip`です。sample root、case、archiveはlink先へ`exists()`で接触する前に`lstat`し、symlink／junction／reparse pointを拒否します。

外装はMalwareBazaar互換の固定password `infected`だけを受け付けます。detectorも同じ固定password契約のため、custom passwordはstage開始前に拒否します。

classifierは`--malware-type`なしの全registry独立分類として実行します。固有handlerへ進むには次の全条件が必要です。

- family一致、`high`／`medium` confidence、解決済みcampaign。
- 根拠が`known_outer_sha256`、`known_inner_sha256`、`type_detector_structure`のいずれか。
- 対象familyのevaluationが正確に1件で、`error`が`null`、`automatic_route_eligible`が`true`。
- triage memberが正確に1件で、そのSHA-256がcase名と一致。
- 親が外装ZIPを専用permissionのtemp directoryへO_EXCLで1回だけstream copyし、同時にouter SHA-256を計算。open前後のdevice／inode／size／mtimeを比較し、全子stageへ同じimmutable snapshotだけを渡す。`triage.outer_sha256`と`classification.observations.sha256`もこのSHA-256へ一致。
- top-level `type_detector.inner_sha256`と対象evaluationの`detection.observations.inner_sha256`がcase／member SHA-256と一致。

outer archive全体を処理するため、複数member archiveは自動処理しません。各caseはatomicな`.analysis-lock` directoryで排他し、同時実行または未確認のstale lockがあれば自動削除せず停止します。snapshotは全stage終了後に再hashし、成功・失敗・割り込みのいずれでも単一fileと専用temp directoryだけをcleanupします。既存output treeの走査には100,000 entry上限を設け、symlink／reparse point、hardlink、特殊file、過大treeを拒否します。

## Family成果transaction

既存`analysis-output`はstrictなschema 2 `batch-run-summary.json`を認証し、`sample_sha256`、現在入力の`outer_sha256`、`member_sha256`、`family`、`member_type`、解決済み`campaign_type`、重複のない`completed_stages`、`executed=false`、`network_contacted=false`がすべて一致するときだけ、`.analysis-output-previous-<UUID>`へ原子的に退避します。2 fieldだけの旧summaryや別outer成果は自動移行せず、明示移行または再解析が必要です。fresh outputで全stageとsummary生成を行います。

途中失敗や割り込みではfresh成果を`.analysis-output-failed-<UUID>`へ隔離し、旧成果があれば`analysis-output`へ原子的に復元します。旧成果がなければoutputを残さずretry可能にします。rollback失敗時は元の例外とrollback失敗を両方報告します。previous／failed成果は自動削除しません。

```bash
python analysis-framework/invoke_family_batch.py \
  --family agenttesla \
  --sample-root /srv/malware-lab/AgentTesla
```

## Ghidra headless import

project名は安全な単一識別子、targetはpayload root内の通常file、project directoryはpayload tree外に限定します。既存の`.gpr`／`.rep`があれば拒否し、fresh project名を必須とします。成功後は新規`.gpr`が通常file、任意`.rep`が通常directoryで、いずれもsymlink／reparse pointでないことを確認します。

Windows batch境界ではexecutable path、project directory、project名、全target pathに`&|<>^()%!`、CR/LF、NUL、double quoteがあれば拒否します。空白は許可します。Ghidra childからも8種類のsecretを除去し、親process timeoutを適用します。

## JSONと終了code

分類、profile、probe結果は上限付きUTF-8として読み、duplicate key、`NaN`／`Infinity`、過剰nestを拒否します。正常完了は`0`、契約違反・stage失敗は`1`、CLI引数誤りは`2`です。C2 detectorの`1`だけは到達不能として限定許可し、結果JSONを別途検証します。

## Windows VMに残す処理

`analysis-framework/common/analysis_safety_check.ps1`はCIM process／service、Task Scheduler、Registry Run／RunOnce、TCP connection、Microsoft Defenderを読み取り専用で確認します。PE起動、DLL登録、Registry変更、`rundll32`／`regsvr32`、PowerShell reflection、debugger実行はPython entrypointへ含めません。
