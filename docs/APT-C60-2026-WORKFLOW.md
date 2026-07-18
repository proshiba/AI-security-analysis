# APT-C-60 / SpyGlace オフライン解析ワークフロー

この手順は、取得済みの delivery artifact または公開された攻撃者 repository のローカル mirror から、公開可能な hash、layer metadata、SpyGlace config、検知用 pivot を生成します。malware の実行や live C2 への接続は不要です。

## 前提条件

- Git の外にある隔離された解析 directory で作業します。
- download した blob、archive、LNK、復元した PE はすべて悪性として扱います。
- `PYTHONPATH` に repository root と `analysis-framework/src` を設定します。
- Ghidra MCP は localhost だけで待ち受け、明示的な program selector を渡し、任意 script 実行は無効のままにします。
- artifact を変換する前に、取得元と取得時刻を記録します。

PowerShell の設定例です。

```powershell
$Repo = 'C:\Users\Administrator\AI-security-analysis'
$Python = 'C:\Users\Administrator\Tools\Python313\python.exe'
$env:PYTHONPATH = "$Repo;$Repo\analysis-framework\src;$Repo\analysis-framework\common"
Set-Location $Repo
```

## 実行順序

### 1. ローカル Git mirror の棚卸し

収集が許可されている場合にだけ mirror を取得し、到達可能な過去の blob をすべて棚卸しします。

```powershell
& $Python .\analysis-framework\common\repository_history_collector.py --git-dir C:\analysis\mirrors\owner__repo.git --output C:\analysis\inventory\owner__repo.json --export-dir C:\analysis\blobs\owner__repo
```

想定出力には、`commit_count`、commit metadata、重複を除いた全 blob とその path、SHA-256、format、literal IOC 候補が含まれます。collector は content を実行しません。

失敗時は次を確認します。

- `not a git repository`: `--git-dir` が、`HEAD` と `objects` を含む bare mirror directory を指しているか確認します。
- 削除済み content がない: mirror がすべての ref を含むことを確認し、`git rev-list --all` を再実行します。
- `skipped maximum_blob_size`: 隔離 storage の空き容量を確認した後にだけ、明示的な上限を引き上げます。
- 空の repository: liveness の結果を保持し、一度も使われなかったとは推測しません。

### 2. LNK と delivery archive の検査

LNK を開かずに検査します。

```powershell
& $Python .\unpackers\apt_c60_delivery.py --input C:\analysis\quarantine\sample.lnk --kind lnk --report C:\analysis\reports\lnk.json
```

TAR bundle を含む厳密な Base64 carrier は、次のように処理します。

```powershell
& $Python .\unpackers\apt_c60_delivery.py --input C:\analysis\quarantine\contributing.txt --kind base64-tar --payload-output C:\analysis\quarantine\iconcache.dat --report C:\analysis\reports\delivery.json
```

delivery の想定出力には、埋め込まれた URL/action または TAR、install script、順序付き TMI fragment、destination、再構築した payload hash が含まれます。

失敗時は次を確認します。

- carrier が厳密な Base64 ではない: 正しい過去 blob を選んだこと、および HTML や Git LFS metadata でないことを確認します。
- decode 後の data が TAR archive ではない: hash を保持し、layer を未知の carrier と分類します。寛容な deserialization は使用しません。
- 安全でない TAR member または TAR link: 抽出を中止し、path safety 違反を報告します。
- fragment が不足: 対応する commit/version を探します。無関係な commit の fragment を連結しません。
- `copy /b` がない: script encoding と filename を静的に確認し、production logic を変更する前にレビュー済み parser fixture を追加します。

### 3. Repository envelope の復元

統合 extractor は既知の envelope を memory 内で復元できるため、decode 済み PE の書き出しは任意です。reverse engineering のためにだけ書き出す場合は、PE を隔離領域へ保存します。

```powershell
& $Python .\unpackers\spyglace_unpacker.py --input C:\analysis\blobs\encoded.tmp --output C:\analysis\quarantine\recovered.bin --report C:\analysis\reports\unpack.json
```

想定出力は、method、入力と payload の SHA-256、size、role です。対応する変換は literal PE、および `sgznqhtgnghvmzxponum` または `AadDDRTaSPtyAG57er#$ad!lDKTOPLTEL78pE` を使う repeating XOR です。

失敗時は次を確認します。

- 対応 envelope がない: blob hash と file generation を確認し、key を推測するのではなく container または script として検査します。
- role が `unknown_pe`: decode 済み hash を保持し、一般的な静的 PE 検査を実行します。SpyGlace label を強制しません。
- 無効な PE: 範囲外の header または不自然な section 数を拒否します。

### 4. SpyGlace config の抽出

encode 済み repository blob または decode 済み PE のどちらかを直接入力します。

```powershell
& $Python -m extractors.config_extractor --family spyglace --input C:\analysis\blobs\encoded.tmp --output C:\analysis\reports\config.json
```

想定出力には、C2 IP、user ID、request path、mutex、command/API set、custom RC4 key、persistence string、payload hash、envelope method、実行なし・network 接続なしを示す明示 field が含まれます。

失敗時は次を確認します。

- variant を認識できない: 有効な SpyGlace PE が復元されたことを確認し、両方の transform domain を検査します。
- command はあるが C2 がない: version/config layout の変更候補として扱い、regex を広げる前に hash-scoped fixture を追加します。
- path がない: decode 済み string から長さを制限した ASP 風の値を探し、Ghidra で参照を検証します。
- AES 定数が null: その binary に literal として存在しなかったことを意味します。古い report に記載があるという理由だけで値を補いません。
- 推定 URL: IP と path の組合せは pivot であり、HTTP または endpoint が live である根拠ではありません。

### 5. 新規 build の reverse engineering

隔離した decode 済み PE だけを import します。Ghidra MCP の各 call では、必ず正確な program を指定し、次を確認します。

1. command/API decoder が「encode 値と 3 の XOR 後に 1 を減算」を実装していること。
2. config decoder が「encode 値と 2 の XOR 後に 1 を減算」を実装していること。
3. WinHTTP API と、復元した各 ASP path への参照。
4. command dispatch の比較処理と、process、file、screenshot、extension handler。
5. loader persistence の CLSID と payload path。

FLOSS の static mode を二次的な string 情報源として使用します。decode string の timeout や decode string が 0 件であることは tool の制約であり、string が存在しない証明ではありません。

### 6. 受動的なインフラ pivot の生成

```powershell
& $Python .\analysis-framework\malware\spyglace\c2_detector.py --input C:\analysis\blobs\encoded.tmp --output C:\analysis\reports\passive-c2.json
```

この手順は Shodan query text だけを出力し、host を probe しません。provenance と観測時刻を伴う、許可された passive source から得た場合を除き、banner hash、title、certificate hash、JARM は null のままにします。

### 7. 検知と regression test の検証

```powershell
& $Python -m pytest .\unpackers\tests\test_spyglace_unpacker.py .\unpackers\tests\test_apt_c60_delivery.py .\extractors\tests\test_spyglace_extractor.py .\emulators\spyglace\tests\test_lab.py .\analysis-framework\malware\spyglace\tests\test_detection.py -q
```

すべての Sigma 文書を YAML parser で検証し、`yara` が利用できる場合は YARA file を compile します。検知 release には、高・中・低の各信頼度について false positive 解析を含めます。

## 公開可能な出力

commit するのは次の項目だけです。

- raw sample byte、secret、victim data を含まない config/report JSON。
- 取得 hash と変換 provenance。
- 明示した時刻における repository liveness。
- IOC CSV、Sigma/YARA、family/campaign 定義、制約。
- unit test と pydoc。

raw または decode 済み malware、repository mirror、victim device 名を付けた task file、victim data を含む packet capture、live response body は絶対に commit しません。

## 新規 variant の escalation 手順

version が既存 logic に一致しない場合は、未知という結果を保持し、別の campaign/layout branch を追加します。既存 classifier 全体を緩めません。悪性でない最小 fixture を作成し、新しい transform を文書化し、成功入力と malformed input の unit test を追加して、pydoc を再生成し、以前の v3.1.15 case を再実行します。
