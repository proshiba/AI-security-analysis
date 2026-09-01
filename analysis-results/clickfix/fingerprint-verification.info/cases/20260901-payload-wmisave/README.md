# ClickFix配信case: WMIsave

## 結論

`fingerprint-verification.info`から取得された`WMIsave.7z`と、内部の`WMIsave.exe`の
完全hashを確認したClickFix配信caseである。生commandは提供されていないため、誘導文や
clipboardへ貼り付けさせたcommandは未確認であり、推測で補完しない。

取得済みPEのpacking、process候補、永続化command、Polygon経由のAPI解決、clipboard置換は
[正規malware case](../../../../malware/unclassified/versions/unknown/cases/d3fc5ed15a97063e804664d5f379bb7454d103b4defa9ac9e788f1eaa922a675/README.md)
へ分離した。検体、payload、scriptは実行していない。

- case識別子: `20260901-payload-wmisave`
- 配布domain: `fingerprint-verification.info`
- archiveのSHA-256: `2ad9b75c8199982ac4398cfe500246d9a840e7554b1a27e2e7d6b53c1ebe15ae`
- payloadのSHA-256: `d3fc5ed15a97063e804664d5f379bb7454d103b4defa9ac9e788f1eaa922a675`
- command取得済み: `false`
- sandboxへのsample提出済み: `false`
- sandboxからのsample／artifact取得済み: `false`
- sample実行済み: `false`

## 成果物

- [配信チェーン](INFECTION-CHAIN.md)
- [配信ロジック](OVERALL-LOGIC.md)
- [インフラ調査](INFRASTRUCTURE.md)
- [Triage照合](TRIAGE.md)
- [IOC一覧](IOC-LIST.md)
