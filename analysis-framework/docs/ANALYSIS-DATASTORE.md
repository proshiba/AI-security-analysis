# リポジトリ外解析データの保管

## 目的

検体本体、復号済みpayload、memory dump、PCAP、Ghidra project、非公開の復元profileなど、Gitリポジトリへ格納しない解析データは、解析対象ごとに暗号化ZIPへまとめて次のS3 bucketへ保管します。

- bucket: `malware-analysis-datastore-720232834682`
- オブジェクトキー: `analysis-targets/<target>/<YYYY>/<MM>/<target>-<UTC timestamp>-<manifest hash>.zip`
- ZIPパスワード: `infected`
- ZIP暗号化: WinZip AES-256
- S3サーバー側暗号化: SSE-S3 (`AES256`)

異なる解析対象を1つのZIPへ混在させません。同一キャンペーン内でも親検体またはcaseが異なる場合は、親子関係をmanifestや公開メタデータに記録した上で別targetとします。

## 保存するものと保存しないもの

保存対象は、再解析に必要なraw検体、抽出物、復号物、dump、通信capture、toolの非公開raw出力です。公開可能なハッシュ、IOC、静的解析結果、検知rule、再現用scriptは従来どおりリポジトリへ保存します。

次の情報はS3 archiveにも入れません。

- GitHub、VirusTotal、Triage、AWSなどのAPI keyやtoken
- AWS credential file、`.env`、`creds.txt`、SSH秘密鍵
- ユーザー情報やホスト固有情報で、解析再現に不要なもの

マルウェアから復元した資格情報や鍵素材を証跡として保存する必要がある場合は、ホスト資格情報と明確に分離し、公開文書には値を出さず、対象別の暗号化ZIPだけへ保存します。

## 実行方法

AWS CLI v2と`analysis-framework/requirements.txt`の依存パッケージが必要です。ホストへ付与されたIAM roleを使用し、access keyを引数や設定ファイルへ書きません。

```powershell
py -3.13 .\analysis-framework\common\archive_analysis_datastore.py `
  --target guloader-xloader-8d96249aa92bee27 `
  --source C:\tmp\guloader-xloader-triage-longrun-20260808 `
  --source C:\tmp\xloader-20260806-fully-recovered-v4.bin `
  --report .\.work\datastore-reports\guloader-xloader-8d96249aa92bee27.json
```

### daily解析を検体単位へ分離する

50検体daily runのsource、one-shot private結果、Ghidra raw結果を保管する場合は、collection全体をそのままarchiveへ渡しません。最初に次のhelperでcase別の物理copyを作成します。出力先はrepository外を指定し、`--case-sha256` は1回につき1件だけ指定します。helperは省略や複数指定をfail-closedで拒否するため、容量を制御しながらcaseごとに逐次実行してください。

```powershell
py -3.13 .\analysis-framework\common\stage_case_analysis_datastore.py `
  --repository C:\work\AI-security-analysis `
  --collection-id malwarebazaar-windows-20260902-0050 `
  --source-root C:\private\daily-runs\daily-20260902\malwarebazaar-windows-20260902-0050\source `
  --one-shot-root C:\work-private\jobs\daily-job\analysis `
  --ghidra-root C:\private\daily-runs\daily-20260902\malwarebazaar-windows-20260902-0050\ghidra-static-results `
  --output-root C:\work-private\daily-orchestrations\daily-20260902\case-datastore-staging `
  --case-sha256 <case SHA-256>
```

helperは、取得済み暗号化source ZIP、当該caseのone-shot directory、当該caseのrelationshipから到達するGhidra objectとimport-staging PEだけをrole別prefixへ物理copyします。collection共通の `input-relationships.json` と `private-artifact-validation.json` はそのままcopyせず、当該caseだけへ絞り、絶対pathをstaging相対pathへ置換した派生manifestを作ります。複数caseで共有されるPEの `program-result.json` も対象caseのrelationshipだけを残して派生させ、他caseの識別子を持ち込みません。hardlink、symlink、junction、秘密値らしいfile名／内容、現在hostのhome path、不完全なGhidra run、case集合やSHA-256の不一致はfail-closedで拒否します。検体の展開・実行やnetwork接触は行いません。

標準出力の各 `cases[].archive_arguments` を、同じcaseの `--target` と `--source` として本archive helperへ渡します。`--report` はrepository外のcase別pathを指定します。異なるcaseのstaging directoryを複数の `--source` で同じ呼出しへ渡してはいけません。

```powershell
py -3.13 .\analysis-framework\common\archive_analysis_datastore.py `
  --target malwarebazaar-windows-20260902-0050-<case SHA-256> `
  --source C:\work-private\daily-orchestrations\daily-20260902\case-datastore-staging\<target> `
  --report C:\work-private\daily-orchestrations\daily-20260902\archive-reports\<target>.json
```

各caseを `stage → archive → upload → remote検証 → receipt保存` の順で完了させてから次のcaseへ進みます。remote検証receiptを照合するまでは、そのcase stagingを削除しません。検証後に削除してよいのは、archive時のsource-tree SHA-256、file数、総sizeと再照合できた、helper作成の当該case owned stagingだけです。元のsource、one-shot結果、Ghidra結果は自動削除しません。

`daily_analysis_orchestrator.py` の `private_archive` も、source取得、one-shot private解析、Ghidra解析が完了したsample collectionには同じ逐次処理を使用します。source全体、one-shot job全体、完了済みGhidra出力全体を別々のbulk archiveへ入れる経路は使用しません。解析途中またはupstream失敗時のGhidra checkpointと、caseへ帰属しないdaily newsは、再開情報を失わないため独立targetとして保管できます。case別archiveが失敗した場合はそのcaseで停止し、remote検証前のowned stagingを保持します。

日次requestでGhidra stageを明示的に無効化した場合も、sourceとone-shot private結果はcase別に分離して保管します。この経路では存在しないGhidra rootを要求せず、staging manifestへ `ghidra.status: not_requested` を記録します。Ghidra成果物が存在するかのような補完は行いません。

`--report`が出力するupload検証receiptには、保管先objectや実行基盤の照合情報が含まれます。これはローカル検証専用とし、リポジトリ外またはGit管理外の`.work`配下へ保存してください。`analysis-results`や`ui`へ配置せず、`datastore-upload.json`を公開成果物としてcommitしたり、READMEからリンクしたりしません。CLIはリポジトリ内の`.work`以外を保存先に指定した場合、upload開始前に処理を拒否します。

処理は次の順序でfail-closedに実行します。

1. source配下のsymlink、junction、reparse point、hardlink、特殊file、資格情報名を拒否する。
2. 各fileを単一handleへ固定し、open前後と読取後のdevice／inode、link数、size、mtimeを照合しながらSHA-256を計算して、絶対pathを含まないmanifestを生成する。
3. ZIP格納時にも列挙時のfile identityを再照合し、同じ単一handleから全memberをpassword `infected`のWinZip AES-256で暗号化する。列挙後のpath差替えやhardlink追加は拒否する。
4. ZIPを復号して全memberを再ハッシュする。
5. `aws sts get-caller-identity`と`HeadBucket`でroleとbucketを確認する。
6. 同一object keyがないことを確認し、SSE-S3とSHA-256 metadata付きでuploadする。
7. `HeadObject`でsize、SSE-S3、archive SHA-256、manifest SHA-256、targetを照合する。
8. 検証成功時だけ一時ZIPを削除する。sourceそのものは自動削除しない。

失敗時は再試行できるようにstaging pathを標準エラーへ表示し、暗号化ZIPを保持します。`--keep-local-archive`を指定すると成功時もstagingへ残します。

## 復元と照合

取得時はAWS CLIで対象objectをダウンロードし、まずobject metadataの`archive-sha256`とローカルZIPのSHA-256を照合します。その後password `infected`で展開し、ZIP内`_analysis_datastore_manifest.json`に記録された各fileのSHA-256を照合します。検体やpayloadは実行せず、静的解析pipelineへ入力します。
