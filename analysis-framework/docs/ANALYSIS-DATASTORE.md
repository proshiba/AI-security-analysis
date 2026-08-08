# リポジトリ外解析データの保管

## 目的

検体本体、復号済みpayload、memory dump、PCAP、Ghidra project、非公開の復元profileなど、Gitリポジトリへ格納しない解析データは、解析対象ごとに暗号化ZIPへまとめて次のS3 bucketへ保管します。

- bucket: `malware-analysis-datastore-720232834682`
- object key: `analysis-targets/<target>/<YYYY>/<MM>/<target>-<UTC timestamp>-<manifest hash>.zip`
- ZIP password: `infected`
- ZIP encryption: WinZip AES-256
- S3 server-side encryption: SSE-S3 (`AES256`)

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

処理は次の順序でfail-closedに実行します。

1. source配下のsymlink、junction、reparse point、特殊file、資格情報名を拒否する。
2. 各fileのSHA-256とsizeを計算し、絶対pathを含まないmanifestを生成する。
3. 全memberをpassword `infected`のWinZip AES-256で暗号化する。
4. ZIPを復号して全memberを再ハッシュする。
5. `aws sts get-caller-identity`と`HeadBucket`でroleとbucketを確認する。
6. 同一object keyがないことを確認し、SSE-S3とSHA-256 metadata付きでuploadする。
7. `HeadObject`でsize、SSE-S3、archive SHA-256、manifest SHA-256、targetを照合する。
8. 検証成功時だけ一時ZIPを削除する。sourceそのものは自動削除しない。

失敗時は再試行できるようにstaging pathを標準エラーへ表示し、暗号化ZIPを保持します。`--keep-local-archive`を指定すると成功時もstagingへ残します。

## 復元と照合

取得時はAWS CLIで対象objectをダウンロードし、まずobject metadataの`archive-sha256`とローカルZIPのSHA-256を照合します。その後password `infected`で展開し、ZIP内`_analysis_datastore_manifest.json`に記録された各fileのSHA-256を照合します。検体やpayloadは実行せず、静的解析pipelineへ入力します。
