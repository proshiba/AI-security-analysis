# Hatching Triage照合

## 結果

- domain: `hdz7omr1.nextbahis.blog`
- 照合日時: `2026-08-02T22:43:08.795512+00:00`
- 検索結果: `domain:` 0件
- 公開一致: `0`件
- 非公開一致の公開成果物への転記: `0`件を除外
- API error: `0`件

公開済み解析との一致は確認できませんでした。

## 調査方針

Triageの既存解析を`domain:`、取得済み完全URLの`url:`、取得済みhashの`sha256:`で照合し、
公開sampleだけについてoverviewと最大2件のbehavioral reportを要約しました。プロセス名、command SHA-256、通信候補、抽出ファイル、
memory由来resourceの有無を残します。raw command、private sample情報、API keyは公開しません。

## 未実施操作

- 新規sample提出: 実施していません。
- 元sample、dumped file、memory dump、PCAPのdownload: 実施していません。
- ローカル実行: 実施していません。

artifactを取得する場合は対象taskと保存先を明示し、`.work`配下でhash検証してから別工程で扱います。

## 参照

- [Triage Search API](https://tria.ge/docs/cloud-api/search/)
- [Triage Samples API](https://tria.ge/docs/cloud-api/samples/)
- [Triage解析種別](https://tria.ge/docs/analysis/)
