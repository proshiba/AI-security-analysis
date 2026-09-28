# 2026-09-26 C2監視のオフライン準備

状態：候補計画のみ。ライブ確認は未実施であり、日次解析の完了条件を満たしていない。

## 作成した計画

[候補インベントリ](candidate-inventory.json)と[完全一致対象計画](targets.json)を、全履歴の公開IOCおよび2026-09-26のニュースIOCから生成した。通常ホスト220/220、endpoint314件（既知portのサービス候補295、DNS-only19）、IOCファイル4,055件、解析エラー0件である。通常ホスト一覧化のカバレッジは100%であり、悪性・到達可能性・C2稼働の確認率ではない。

本日ニュース由来のhandoffは12件。未確認テレメトリ候補 `apm.hexin[.]cn` と `58.220.49[.]156` は、source manifest・説明文へ束縛したreviewで除外した。[根拠監査](../../daily-news-malware/2026-09-26/SOURCE-REVIEW.md)を参照する。50検体の初回静的成果物の公開後に再集計したが、初回の確定C2は0件のため、endpoint数は変わらなかった。

## 未実施の段階

- 現在の実行に対するライブC2接触の明示許可：回答待ち。
- 能動的DNS／TCP／TLS／NSEによる対象確認：未実施。
- GeoLite2 City／ASNの再取得と公式checksum検証：未実施。既存Cityのbuildは2026-09-22で、ライブ前の鮮度gateを満たさない。
- ライブ観測結果、稼働判定、protocol一致判定：未生成。

許可後もreview済みNSE・完全一致endpoint・送受信と時間の上限に限定する。port不明のhostをDNS-onlyからサービス稼働へ昇格しない。検体や受信payloadの実行、認証、偽装登録・tasking、redirect追従、stage取得、port range scanはこのオフライン計画により許可されたものではない。
