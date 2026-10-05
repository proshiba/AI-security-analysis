# RemcosRAT 最新50検体の静的解析とC2ハンティング

## 結論

MalwareBazaarの `RemcosRAT` 署名から新しい順に固定した50件を、すべて実行せず解析しました。
選定時刻は `2026-10-04T14:07:10.697795+00:00`、対象のfirst seen範囲は `2026-09-30 08:27:43` から `2026-10-04 07:16:05` です。
元アーカイブと内側SHA-256は 50/50件で一致しました。
ルートはPE 3件、配送層 47件でした。
ルートPEと親子SHA-256で結合した終端artifactから、7件をRemcosとして静的確認し、
重複を除く7件のC2を独立に復元しました。
Triageの既存公開解析は全50件にあり、26件から
35件のC2が報告されています。外部報告だけの値はローカル確認済みとは分離しています。

## ローカルで検証した設定

| 親SHA-256 | バージョン | C2 | TLS | 間隔／初回遅延 | peer certificate SHA-256 |
| --- | --- | --- | --- | --- | --- |
| `13045b384561af13da3cbea5be0440e1939e3765b66fbd43a4f64990f60f072c` | `7.3.1 Pro` | `zeife.giize.com:2404` | 無効 | 1秒／0秒 | `なし` |
| `3797d5082f3612a2493ce6430ed09a61922573f6871401f95b0d2e735a12ada1` | `7.3.1 Pro` | `catground1957.casacam.net:7788` | 有効 | 1秒／0秒 | `334f7074f9eb57f009d82aa363d12079b10d40d352b7a47df409f282f2fd38b5` |
| `7250576a3cb7164bf383d89683267604dd1a5d36e1a35f22b5bef2d9f29402e5` | `7.3.1 Pro` | `172.94.15.100:6075` | 有効 | 1秒／0秒 | `5fefab09eab4f5c9640b02064611f98ec9b8a02f2676057cda9e7da234450eac` |
| `9121ef0f2d7b2cc3c887420ecb1eae214db9cb780433d11565ab8c98a6ad99ec` | `3.8.0 Pro` | `onetouchfromlifeto.ddns.net:4489` | 有効 | 1秒／0秒 | `7d06175014b1e78f3270d38dae74c02d903106eabea6fe34934ebe5e055d42f7` |
| `9f0df64cc8a15b2c96e639a975acb9f54ff26721dc60a8035d4bbc65476485e7` | `3.8.0 Pro` | `155.103.69.174:4981` | 有効 | 1秒／0秒 | `381dde7342bfd09f216037ba2fbcc4de5349fd5a9bde0adcfcbae3f4ec613aa3` |
| `9fe3245959f6b42e7ac6a25308a439d89851933563cc868f4eeb1e9824be95ee` | `7.3.1 Pro` | `bk.aerovisioncity.com:54198` | 有効 | 1秒／0秒 | `a60dde327dfcfd9b05086eb875d172b95f2e8ecff093f8a881dcdbd8af581f46` |
| `f1610df683fc2543d951f5f83ffc425963a4cc71562a47637987adbf2788d3d1` | `7.3.1 Pro` | `23.132.164.3:2404` | 有効 | 1秒／0秒 | `f85cbb2278aec97c94262447373feca642adf5112f7f726c7f9f6af35de60594` |

バージョン分布は `3.8.0 Pro` 2件、`7.3.1 Pro` 5件 でした。TLS有効6件、無効1件です。
設定中の秘密鍵は存在有無だけを記録し、値もhashも公開していません。

## C2ハンティング

[c2-hunting.json](c2-hunting.json) には35 endpointを収録しています。
各項目は `sources` で次の2段階に分かれます。

- `confirmed_static_configuration`: 当方のRC4 SETTINGS復号器で終端PEから確認した値。
- `external_sandbox_reported_configuration`: Triage既存公開解析の設定要約にだけ現れた値。

IP／hostnameとportのShodan受動検索式を生成しています。TLS有効なローカル検証設定では、
設定内 peer certificate SHA-256 6件について Shodan／Censys のpivotも生成しました。
これは実サーバから採取した証明書ではなく、Remcos設定に埋め込まれたC2公開証明書のhashです。
能動スキャン、DNS解決、C2接続、liveness確認は実施していません。

## 自動解析の改善

- PE `RCDATA/SETTINGS` の一意性、境界、先頭鍵長、RC4、delimiter、field数、index 0のC2構造を検証します。
- 通常PEに加え、Triage memory imageのsectionをファイル配置へ再構築し、同じ抽出器へ自動投入します。
- C2、TLS flag、botnet、接続間隔、初回遅延、mutex hash、agent／peer certificate hash、バージョンを抽出します。
- legacy schemaの第3fieldはTLSと決め打ちせず、認証値の可能性があるため非公開で保持します。
- fixed cohort manifest、Triage exact-hash要約、限定取得artifactを親子SHA-256で結合します。
- Triage artifactはAES-256 ZIPからメモリ上で読み、再構築PEや復号済み設定を平文保存しません。

標準1検体解析では `analysis-framework/common/analyze_sample.py` が Remcos終端PEとmapped PEを自動判定します。
集合評価は `analysis-framework/malware/remcosrat/analyze_corpus.py`、限定取得artifactの一括解析は
`analysis-framework/malware/remcosrat/analyze_triage_artifacts.py` を使用します。

## 配送層と未確認点

50件中47件はJS、VBS/VBE、BAT、HTA、Office、MSI、ZIP等の配送層でした。
外部既存解析ではRemcosに加えてGuLoader／DonutLoader等のローダー表示もあり、配送層のラベルだけで終端familyを確定していません。
24件はTriage公開要約にも設定C2がなく、現時点ではC2未回収です。
また、外部ラベルと内部YARAが競合するケースは、終端SETTINGSを復元できるまで暫定扱いです。

## 根拠資料

- [Elastic Part One](https://www.elastic.co/security-labs/threat-command/dissecting-remcos-rat-part-one): `SETTINGS`、鍵長＋鍵＋暗号文、RC4、delimiter。
- [Elastic Part Three](https://www.elastic.co/security-labs/threat-command/dissecting-remcos-rat-part-three): index 0の `domain:port:enable_tls`、接続間隔、初回遅延、TLS certificate fields。
- [Fortinet Remcos 3.4.0](https://www.fortinet.com/blog/threat-research/latest-remcos-rat-phishing): SETTINGS構造、TLS/AES通信、登録packet、heartbeat、command taxonomy。
- [Cisco Talos decoder](https://github.com/Cisco-Talos/remcos-decoder/blob/master/remcos_decryptor.py): 旧世代RemcosのSETTINGS／RC4復号実装。

## 安全境界

検体実行、受信コマンド実行、C2接続、認証試行、payload実行は行っていません。
endpointや証明書hashはハンティング候補であり、現在の稼働、悪性、同一運用者を単独では証明しません。
