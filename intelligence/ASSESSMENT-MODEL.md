# 相関・評価モデル

## 目的

この文書は、検体間の一致をcampaign、operation、actor帰属へ段階的に評価する基準を定義します。自動scoreは候補の順位付けにだけ使い、帰属結論そのものには使いません。

## エンティティ

継続調査では、次のentityを一意なIDで管理します。

| entity | 主key | 例 |
|---|---|---|
| sample | SHA-256 | 提出検体、loader、payload |
| function | sample + program + function ID | 代表関数、managed method |
| component | review済みcomponent ID | config decoder、loader stub、通信module |
| config | sample + config schema + extraction ID | campaign ID、mutex、C2設定 |
| infrastructure | type + normalized value | domain、IP、endpoint、certificateなどの基盤情報 |
| delivery | delivery ID | archive、installer、side-loading bundleなどの配布物 |
| campaign | campaign ID | 同じ活動として相関したcase集合 |
| operation | operation ID | 複数campaignを束ねる運用仮説 |
| actor | 正規化actor ID | 公開報告に基づく脅威アクター |
| source | source ID +取得日時 | vendor、CERT、MalwareBazaar、内部解析 |

family名、MalwareBazaar tag、collection membership、ファイル名はentityの属性であり、それだけで相関edgeにはしません。

## エッジ

edgeには必ず`source`、`observed_at`、`recorded_at`、`confidence`、`review_state`を持たせます。

| edge | 意味 |
|---|---|
| `contains` | sampleが別artifactを内包する |
| `loads` | hostがDLLやpayloadをloadする |
| `derived_from` | 復号、展開、変換による親子関係 |
| `code_similar_to` | 関数またはcomponentのコード類似 |
| `uses_config` | sampleと復元configの関係 |
| `communicates_with` | process帰属を持つC2・通信先 |
| `distributed_from` | 配布先とartifactの関係 |
| `resolves_to` | domainとIPの時間付き関係 |
| `served_certificate` | endpointとcertificateの関係 |
| `observed_in_campaign` | entityとreview済みcampaignの関係 |
| `candidate_part_of_operation` | campaignとoperation候補の関係 |
| `attributed_by_source` | sourceがcampaign・operationをactorへ帰属した事実 |

`attributed_by_source`は「repositoryが帰属を確認した」という意味ではありません。公開情報がその主張をした事実と、repository内での評価を分離します。

## 証拠の強さ

### 強い証拠

- SHA-256などartifactの完全一致
- 親子sampleで埋込payload hashが一致
- 固有config ID、固有暗号鍵、固有protocol fieldの一致
- 希少な複数IOCが同じ役割と近い時期に一致
- review済みの固有配布chainとcomponentの組合せ
- 信頼できるOSINTの完全一致hash

### 中程度の証拠

- 情報量の高い代表関数とcall graph近傍の一致
- certificate、domain、endpointの時間付き再利用
- 同一builderを示す複数の非汎用feature
- 同じdecoyテーマ、署名付きhost、side-loading DLL、config形式の組合せ
- 期間と標的が重なるTTP集合

### 弱い証拠

- IP単独
- family名、community tag、collection membership
- imphash、SimHash、文字列、ファイル名の単独一致
- 一般的API、compiler/runtime関数、公開library
- DDNS、CDN、cloud storage、共有SMTPの単独一致
- 同じ国、言語、業種だけの一致

弱い証拠は候補探索には使用できますが、campaignまたはoperationへの昇格条件を単独では満たしません。

## 評価段階

### 段階0: observation

単一caseまたは単一sourceで観測した事実です。解釈を加えず、値、役割、取得時刻、根拠を保存します。

### 段階1: relationship candidate

2つ以上のentityに一致がある状態です。自動生成してよい段階ですが、generic値と共有libraryを除外できていない可能性を明記します。

### 段階2: campaign candidate

次のいずれかを満たし、人手レビューを通過した集合です。

- 強い証拠が1件あり、時期・役割に重大な矛盾がない。
- 独立した中程度の証拠が2軸以上あり、少なくとも1軸がIOC以外である。
- 同じ配布chainで親子artifact関係が確認されている。

campaign候補は、同一actor、同一operator、同じmalware開発者を意味しません。

#### campaign候補の同一性とlineage

campaign候補IDは内容依存で生成されるため、実体の追跡には使えません。`correlate_campaigns.py`は`{families, campaign_types, 共有指標}`のSHA-256から`campaign_id`を作るので、メンバーが同じでも共有指標集合が変われば別IDになります。週次で同じ候補を追跡するため、次を守ります。

- 候補の同一性は、`campaign_id`ではなくメンバーSHA-256集合の重なり（Jaccard係数、包含関係）で判定する。
- 週をまたいで実体を追う安定lineage IDを別に持ち、その週の`campaign_id`と対応付ける。
- 候補の増減は、指標集合やprevalence閾値の跨ぎによる見かけ上の付け替えと、メンバーの実変化（`grew`/`shrank`/`merged`/`split`/`new`/`dissolved`）を区別して記録する。

詳細な週次手順は`RECURRING-TASKS.md`の`INT-W06`を参照します。

### 段階3: operation candidate

次をすべて満たす場合だけ昇格します。

1. review済みcampaignが2件以上ある。
2. コード・config、インフラ、配布・実行、時間・標的のうち3軸以上で関係がある。
3. 3軸のうち少なくとも1つは強い証拠、または相互に独立した中程度の証拠2件である。
4. 活動期間が重なる、連続する、または再開として説明できる。
5. `共通builder`、`共通hosting`、`共通initial-access提供者`などの代替仮説を評価している。
6. 重大な否定証拠が未解決のまま残っていない。

複数の異なるmalware familyが含まれることはoperation候補の情報量を高めますが、必須条件ではありません。

### 段階4: actor attribution hypothesis

operation候補にactor名を関連付ける仮説です。次をすべて要求します。

1. actor名を明記した信頼できるOSINT sourceがある。
2. 完全一致hash、固有campaign ID、固有インフラ、固有配布chainのいずれかでsourceとrepository内entityを接続できる。
3. OSINTの主張とは独立したrepository内証拠軸がある。
4. actorの別名、競合帰属、情報源間の依存関係を確認している。
5. 人手レビューで`confirmed`、`inferred`、`unverified`相当の確度を付けている。

actor名を自動labelとして付与しません。

## 時間の扱い

`first_seen`には少なくとも次を分けます。

- `sample_first_seen`: 検体提供元での初回観測
- `infrastructure_first_seen`: passive情報での初回観測
- `campaign_first_seen`: campaignとして確認できた最初の活動
- `source_published_at`: 公開報告の発行時刻
- `repository_recorded_at`: repositoryへ記録した時刻

公開日を攻撃発生日として扱いません。時間付きedgeでは24時間、7日、30日、90日のwindowを別に評価し、長期間離れた再利用は同時運用と分けます。

### 現在利用できる時間軸の制約

repositoryは安全方針により受動DNS、証明書透明性、WHOISを既定で取り込みません。したがって現時点で安定して使える時間軸は`sample_first_seen`（検体提供元の初回観測）と`repository_recorded_at`が中心で、`infrastructure_first_seen`は原則として未取得です。週次運用では次を守ります。

- 時間付きの結論は`sample_first_seen`の範囲に限定し、インフラの初回観測を持たない前提を成果物へ明記する。
- campaign候補の内部では、メンバーの`sample_first_seen`の広がりを見て、短期バースト型か長期再利用型かを区別する。単一時点への集中と長期の散在を混同しない。
- インフラのlifecycle（`active`/`dormant`/`reassigned`/`sinkholed`）を断定する場合は、それが受動情報ではなくrepository内観測に基づく限定的な推定であることを明記する。

## prevalenceと情報量

repository内で頻出する値ほど相関への寄与を下げます。

- 共有library、runtime、一般的APIは原則として除外する。
- IP、domain、certificateはcase・family・campaignをまたぐ出現数を保持する。
- 新しいcase追加によってprevalenceが上がった場合、過去の候補も再計算する。
- ある時点で希少だった値が後に共有サービスと判明した場合、過去labelを確度低下または撤回できるようにする。

現在のcampaign相関処理は、指標の最大出現数、cluster上限、same-familyとcross-familyの閾値を持ちます。月次backtestでは[相関規則](../analysis-framework/registry/campaign_correlation_rules.json)の変更前後を採用・棄却済みfixtureで比較します。

## 矛盾と確度低下

次の場合は候補を統合せず、確度を下げるか分割します。

- 同じインフラ値だが役割が異なる。
- domainやIPが再割当、sinkhole、共有hosting化されている。
- 時間が重ならず、再開を支える証拠もない。
- config schema、protocol、配布chainが互換性のない形で異なる。
- 類似関数が既知library、compiler生成、packer stubと判明した。
- sourceが同じ基礎providerへ依存しており、独立した裏付けにならない。
- victimologyや活動地域が明確に矛盾する。

棄却は削除ではなく、`rejected`状態と理由を残します。棄却は恒久的な棄却台帳（`intelligence/hypotheses/rejected/`）へ保存し、メンバーSHA-256集合の正規化fingerprintまたは根拠指標・component集合をkeyにします。IDが内容依存で変わっても再照合できるようにし、各記録に棄却理由、否定証拠、棄却日、再評価を許すtrigger（新しい完全一致hash、希少configの追加など）を残します。週次の候補生成後は棄却台帳と照合し、再評価triggerを満たさない既知の棄却をreview queueへ再投入しません。運用手順は`RECURRING-TASKS.md`の「棄却台帳(rejection ledger)」を参照します。

## 確度表現

| 確度 | 意味 |
|---|---|
| `confirmed` | repository内の直接証拠または完全一致で事実関係を確認した |
| `high` | 複数の強い・独立した証拠があり、主要な代替仮説を排除した |
| `medium` | 複数証拠が一致するが、共有基盤やbuilder共有を排除できない |
| `low` | 単一または弱い証拠による探索候補 |
| `unverified` | 情報はあるが、必要な原資料またはrepository内接続を確認していない |
| `rejected` | 反証またはgeneric性により候補から除外した |

campaign相関の`high`とactor帰属の`high`は同じ意味ではありません。評価対象と証拠要件を成果物に明記します。

## review queueの優先順位

優先順位は次の順で上げます。

1. 既知campaignの完全一致artifact hash。
2. 異なるfamily間での希少componentとIOCの同時一致。
3. config、protocol、配布chainの新しい組合せ。
4. 休止していた既知インフラの再観測。
5. 未分類caseがreview済みcampaignへ接続した候補。
6. 高類似だがコード軸しかない候補。

大量の類似pairは、類似度の高さだけで上位にしません。関数の役割、希少性、異なるfamily、時間、IOC・configの補助証拠を重視します。

## operation成果物の必須項目

各operation候補には次を残します。

- 一意なoperation ID
- 評価日、対象期間、現在状態
- 関連campaignとsample
- 関連malware familyと使用段階
- 共有component、config、infrastructure、delivery
- 根拠edge一覧とsource
- 確度と昇格条件の充足状況
- 代替仮説
- 否定証拠と未解決事項
- actor帰属の有無と、その根拠を示したsource
- 次回再評価trigger
- 検知・huntへ還元する特徴

actorやoperationの説明文と、検知に使用するIOC・特徴は分離します。説明文から未確認値を自動的にhunt ruleへ移しません。

## 安全性と公開範囲

- 検体や復号payloadを実行しない。
- 検体や未知artifactを外部サービスへ送信しない。
- 既定のOSINT補強は完全一致hashと受動的な公開情報に限定する。
- live C2接続や外部hostへのprobeは、現在のタスクで明示的に許可された場合だけ行う。
- credential、token、URL userinfo、query、fragment、生の秘密値を公開成果物へ残さない。
- 正規署名付きhost、decoy、公開IP確認serviceを単独の悪性IOCにしない。
- sourceの利用条件と引用制限を守り、公開成果物には必要最小限の要約と参照を残す。
