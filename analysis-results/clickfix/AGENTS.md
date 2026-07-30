# ClickFix成果物の運用ルール

- 人が読む文書は日本語で記述し、感染チェーン、実行フロー、module関係をMermaidで図示する。
- caseは`<domain>/cases/<case-id>/`の固定深度とし、domain直下へ日付フォルダを追加しない。
- 選定、ライブ観測、文書生成は`analysis-framework/clickfix/clickfix_daily_intake.py`を正本とし、1回の対象を50件以内にする。
- provider報告、ライブHTTP観測、静的復元、終端payloadの確認を別の確度として記録する。tagだけでmalware family、campaign、actorを確定しない。
- 生command、生レスポンス、取得本文、token、資格情報はこの階層へ置かない。共有インフラと解析時DNS解決IPは`context_only`とし、`IOC-LIST.md`へ昇格しない。
- 実サイト確認は上限付きGETだけを基本とし、JavaScript、clipboard内容、取得script／binaryを実行しない。POST、form入力、認証、WebDAV変更系method、malware protocolを送信しない。
- 配布binaryまたは完全hashを取得した場合は、ここでは配布関係だけを記録し、canonical malware caseへ別途登録して静的解析する。
- `IOC-LIST.md`は専用generatorと共通`generate_ioc_lists.py`の双方で一致させ、`analysis-results/IOC-INDEX.md`へ索引化する。
- payloadを取得できないcaseも`INFRASTRUCTURE.md`と`infrastructure.json`を必須とし、current DNS、RDAP、CT、leaf証明書、netblock、ASN、InternetDBを時点付きで残す。共有基盤の一致だけでC2／campaignを確定しない。
- `TRIAGE.md`と`triage-evidence.json`を必須とし、Triageの公開済み解析をdomain／取得済み完全URL／hashで照合する。process、command hash、network、dump、memory、PCAP候補を確認し、private解析とraw commandは公開しない。
- Triageへの新規提出とartifact downloadは自動化しない。必要時は明示的な調査工程として`.work`配下へ保存し、hash、取得元、task IDを記録する。
- passive providerが429または一時的5xxを返した場合は、成功済み証跡を維持し、部分結果とHTTP statusを残す。取得失敗をnegative evidenceとして扱わない。
