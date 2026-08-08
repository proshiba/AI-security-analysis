# クロスプラットフォーム実行メモ

## 追加したファイル

既存のPowerShell、Python、設定、解析結果は変更・削除していません。今回追加したファイルは次のとおりです。

| ファイル | 用途 |
|---|---|
| `analysis-framework/invoke_analysis.py` | `Invoke-Analysis.ps1` と同じ標準one-shot／旧ValleyRATフローをWindowsとLinuxから起動する入口 |
| `analysis-framework/invoke_family_batch.py` | `Invoke-FamilyBatch.ps1` のAgentTesla／RemcosRAT一括静的解析 |
| `analysis-framework/common/import_ghidra_project.py` | `Import-GhidraProject.ps1` のGhidra headless import |
| `analysis-framework/tests/verify_known_families.py` | `Test-KnownFamilies.ps1` の既知AgentTesla／RemcosRAT回帰確認 |
| `analysis-framework/malware/valleyrat/tests/verify_known_samples.py` | `Test-KnownSamples.ps1` の既知ValleyRAT回帰確認 |
| `analysis-framework/tests/test_cross_platform_orchestration.py` | OS別Python検出、引数list、routing、summary、Ghidra境界の単体テスト |
| `CROSS-PLATFORM-NOTES.md` | この実行手順とOS固有境界 |

`invoke-analysis.sh` のようなshell固有wrapperは不要です。Python entrypoint自体がWindowsとLinuxで同じCLIを提供します。作業開始時点では置換対象となる既存の`invoke-analysis.sh`はありませんでした。

## Pythonの選択

`--python`を指定した場合はその値を子stageに使います。省略時は実行中のOSに応じて次の順で選択します。

1. Windows: `analysis-framework/.venv/Scripts/python.exe`
2. Linux: `analysis-framework/.venv/bin/python`
3. 上記が存在しない場合: entrypointを起動した`sys.executable`

venvのactivateはshellのPATHを変更する便宜的な操作です。entrypointはvenv内のPythonを直接起動するため、activateしなくても同じ環境を使用できます。

## Windowsでの実行

Python 3.11以上を使い、隔離した解析環境でvenvを作成します。

```powershell
cd <repo-root>\analysis-framework
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python .\invoke_analysis.py `
  --sample C:\malware-lab\samples\sample.zip `
  --output-directory C:\malware-lab\out
```

activateせずに直接起動する場合は次の形式です。

```powershell
.\.venv\Scripts\python.exe .\invoke_analysis.py `
  --sample C:\malware-lab\samples\sample.zip `
  --output-directory C:\malware-lab\out
```

## Linuxでの実行

```bash
cd <repo-root>/analysis-framework
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python invoke_analysis.py \
  --sample /srv/malware-lab/samples/sample.zip \
  --output-directory /srv/malware-lab/out
```

activateせずに直接起動する場合は次の形式です。

```bash
.venv/bin/python invoke_analysis.py \
  --sample /srv/malware-lab/samples/sample.zip \
  --output-directory /srv/malware-lab/out
```

すべてのpathは`pathlib.Path`で構築し、子processはshell文字列ではなく引数listで起動します。空白を含むpathを手動で連結またはescapeする必要はありません。

## `Invoke-Analysis.ps1`との引数対応

| PowerShell | Python |
|---|---|
| `-Sample` | `--sample` |
| `-OutputDirectory` | `--output-directory` |
| `-ProfilePath` | `--profile-path` |
| `-NetworkEvidence` | `--network-evidence` |
| `-MalwareType` | `--malware-type` |
| `-VirusTotalApiKey` | `--virus-total-api-key`。省略時は`VT_API_KEY` |
| `-AllowLiveC2Check` | `--allow-live-c2-check` |
| `-CollectJarm` | `--collect-jarm` |
| `-ArchiveMode` | `--archive-mode {auto,raw,malwarebazaar}` |
| `-AssessmentOnly` | `--assessment-only` |
| `-LegacyValleyWorkflow` | `--legacy-valley-workflow` |
| `-Python` | `--python` |

既定では`common/analyze_sample.py`へ`--input`、`--output`、`--archive-mode`を渡します。profile、network evidence、live C2、JARM、または`--legacy-valley-workflow`を指定した場合は、PowerShell版と同じ旧ValleyRAT分岐を使います。旧フローは`classification.json`を読み、対応するvvaSまたはMSI/CAB handlerを実行し、最後に`run-summary.json`を出力します。

live C2確認とVirusTotal取得は外部通信です。既定では実行されません。現在の調査で明示的な許可があり、review済みprofileと隔離環境を確認できた場合に限って使用してください。

## ほかの移植済み入口

AgentTeslaまたはRemcosRATの従来batchは次のように実行します。

```bash
python analysis-framework/invoke_family_batch.py \
  --family agenttesla \
  --sample-root /srv/malware-lab/AgentTesla
```

Ghidraは`GHIDRA_HOME`を指定すると、Windowsでは`support/analyzeHeadless.bat`、Linuxでは`support/analyzeHeadless`を自動検出します。`--analyze-headless`で明示指定することもできます。

```bash
python analysis-framework/common/import_ghidra_project.py \
  --payload-directory /srv/malware-lab/payload \
  --project-directory /srv/malware-lab/ghidra-projects \
  --project-name sample-static \
  --target loader.dll \
  --target host.exe
```

既知検体の回帰確認にもPython版を利用できます。

```bash
python analysis-framework/tests/verify_known_families.py \
  --agenttesla-root /srv/malware-lab/AgentTesla \
  --remcos-root /srv/malware-lab/RemcosRAT

python analysis-framework/malware/valleyrat/tests/verify_known_samples.py \
  --old-sample /srv/malware-lab/valleyrat/old.zip \
  --new-sample /srv/malware-lab/valleyrat/new.zip
```

## Windows VMに残す処理

`analysis-framework/common/analysis_safety_check.ps1`は、WindowsのCIM process／service、Task Scheduler、Registry Run／RunOnce、TCP connection、Microsoft Defenderの有効な脅威を読み取り専用で確認します。これらはWindows固有のsecurity sourceであり、Linux上の不完全な代替結果と同一視できないため、Windows静的・動的解析VMで引き続き既存スクリプトを使用します。

PEの起動、DLL登録、Registry変更、`rundll32`／`regsvr32`、PowerShell reflection、debuggerによる実行は今回のPython entrypointには含めていません。このリポジトリの静的解析では検体を実行しません。Windows固有の挙動を動的に確認する必要がある場合は、別途承認された隔離Windows VMのdynamic-analysis手順として扱います。

Ghidra headless importは静的処理なので移植済みです。ただしGhidra本体と対象architectureに必要なprocessor moduleは各OSへ別途用意する必要があります。Windows専用の既存PowerShell regression wrapperも互換性のため残し、cross-platform利用時は上記Python版を使います。
