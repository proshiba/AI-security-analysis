# マルウェア解析ブラウザUI

`analysis-results/` 配下の公開成果物と `analysis_history.yaml` の解析履歴を、ブラウザだけで検索・閲覧するための静的UIです。サーバーや外部ライブラリは不要で、検体本体には一切アクセスしません。

## 使い方

1. データファイルを生成します(リポジトリの解析結果を更新した後も同じコマンドで再生成します)。

   ```bash
   python3 ui/generate_ui_data.py
   ```

2. `ui/index.html` をブラウザで開きます。ローカルHTTPで開くと、ケースページ内の成果物ファイルへのリンクも辿れます。

   ```bash
   python3 -m http.server 8000
   # → http://localhost:8000/ui/index.html
   ```

CIなどで生成済み `ui/data.js` が最新か確認する場合は次を使います。

```bash
python3 ui/generate_ui_data.py --check
```

## ポータル連携用の静的インデックス（spec v1）

横断ポータル（`proshiba/research_bench`）が `fetch()` する軽量な索引を `ui/api/v1/` に公開します。ポータルはサーバーを持たず、各アプリが公開する静的JSONを手元で索引し、同じ値が複数ソースに現れたことを検出して横串を作ります。

| パス | 内容 |
|---|---|
| `ui/api/v1/meta.json` | 自己紹介。ポータルが最初に読む（site_url、deep_links、embed_css、stats） |
| `ui/api/v1/search.json` | 索引本体（エンティティ一覧） |

```bash
python3 ui/build_portal_index.py            # 索引を再生成
python3 ui/build_portal_index.py --check    # 既存索引との差分を確認
python3 ui/build_portal_index.py --validate # 仕様v1の自己検証だけを実行
```

生成は `generate_ui_data.py` と同じ入力（catalog、caseディレクトリ、campaign相関、`analysis_history.yaml`）から行い、`ui/data.js` は変更しません。UIはそちらに依存し続けます。

エンティティ種別と結合キーの扱い:

- `case`（検体1件）: `id` は `case:<sha256>`、`value` は小文字SHA-256。本文（README／STATIC-LOGIC／FEATURES）は含めず、詳細はdeep linkでUI本体へ渡します。
- `malware`（ファミリ）: `value` は表示名、`aliases` に別名・ファミリkey・表示名から導出した名前を入れます。ポータルは英数字のみ小文字化して突き合わせるため、`ACRStealer／Amatera` のような表記は分解して別名にします。
- `campaign`（相関候補）: `id` は `intel:<campaign_id>`、構成ケースとファミリへ `refs` を張ります。
- `ioc.*`: 同じ値は1エンティティへ畳み、観測元のケースを `refs` に並べます。`host:port` とURLからはホスト単体のエンティティも作り、`ホスト` の `refs` で結びます（これがないとIPでのピボットが効きません）。

索引に入れない値:

- 検体自身のSHA-256と一致するfile-hash IOC（`case` エンティティと重複するため）
- `file_name`、`Ethereumアドレス`（結合キーとして誤結合の元になるため）
- Shodanのクエリfield名など、指標ではない値

`generated_at` はHEADのcommit時刻を使うため、同じコミットからは同じ索引が再生成されます（`--check` は `generated_at` を比較対象から除外します）。

## GitHub Pagesでの公開

`.github/workflows/deploy-pages.yml` により、`main` への push（`ui/`、`analysis-results/`、`analysis_history.yaml` の変更時）と手動実行で自動デプロイします。ワークフローは `data.js` とポータル連携用インデックス（`ui/api/v1/`）を再生成し、`ui/` だけを軽量に配信します（`analysis-results/` 本体は約276MBあるため同梱しません）。

初回のみ、リポジトリ設定で有効化が必要です。

1. GitHubのリポジトリ → **Settings** → **Pages** を開く。
2. **Build and deployment** の **Source** を **GitHub Actions** にする。
3. この変更を `main` へマージすると、ワークフローが走り `https://<owner>.github.io/<repo>/` で公開されます（`/` は `ui/` へリダイレクト）。

補足:

- ケースページの「結果ディレクトリ」「成果物ファイル」「生成元」リンクは、配信に同梱しない代わりに **GitHub上の該当ファイル**（Markdownは自動レンダリング）へ向きます。リンク先は `generate_ui_data.py` が `git remote` またはCIの `MALDB_REPO_SLUG` / `MALDB_REPO_BRANCH` から決定します。ローカルでリポジトリ直下から配信した場合は相対パスにフォールバックします。
- プライベートリポジトリのGitHub Pagesは有料プラン（Pro/Team/Enterprise）が必要です。公開範囲は、リポジトリの公開設定に従います。
- 定期インテリジェンス調査などで `analysis-results/` を更新して `main` に反映すると、Pagesも自動で最新化されます。

## 画面構成

| 画面 | 内容 |
|---|---|
| ダッシュボード (`#/`) | ケース数・ファミリ数・IOC数・ルール数の統計、**入力するとリアルタイムに絞り込む横断検索**、ケース数上位ファミリ、最近追加されたケース |
| 検索 (`#/search`) | ハッシュ・IP・ドメイン・URL・接続先・マルウェア名・別名・キャンペーン候補・ファイル名・タグを横断検索。種別ごとにまとめて表示 |
| ファミリ一覧 (`#/families`) | 全マルウェアファミリのカード一覧 |
| ケース検索 (`#/cases`) | SHA-256、ファミリ、キャンペーン種別、コレクション、C2有無、IOC値、ファイル名の横断検索 |
| IOC検索 (`#/iocs`) | 全ケースの `IOC-LIST.md` を集約したIOC表。種別フィルタと値の一括コピー、各行から横断ポータルのグラフ調査へのpivot（⊕） |
| キャンペーン相関 (`#/intel`) | intelligence調査のcampaign相関候補一覧・詳細（共有指標、相関ケース、ルール、制約） |
| C2稼働状況 (`#/c2`) | C2監視ランの最新観測。**世界地図へのIPプロット**（ホイールで拡大／ドラッグで移動／点クリックで一覧を絞り込み）、**入力するとリアルタイムに絞り込む検索窓**（ファミリー・ホスト・IP・国／都市・ASN・観測結果・関連ケース。空白区切りはAND）、**応答なしendpointの表示トグル**、endpoint一覧（到達・C2稼働・手法上限のconfidence）、**ドメインの解決IP推移**、観測の読み方と安全境界 |
| ファミリ別ページ (`#/family/<key>`) | ケース一覧、YARA/Sigmaルール、概要・OSINT・技術解析・版情報などの文書タブ |
| ケース別ページ (`#/case/<sha256>`) | 判定・検体メタデータ、C2、挙動・機能、検体特徴、IOC表、検知ルール、解析履歴タイムライン、ケースREADME、成果物ファイルへのリンク |

ヘッダーの検索ボックスに完全なSHA-256を入れると該当ケースへ直接移動します。`#/case/<SHA-256先頭一致>` でも一意に決まればリダイレクトします。

## 検索

ヘッダーの検索ボックスと `#/search` から横断検索できます。ファミリ一覧だけでなく、値そのものから辿れるようにしています。

検索できる対象:

| 対象 | 例 |
|---|---|
| ハッシュ（SHA-256／SHA-1／MD5、先頭一致可） | `3f091457`、完全一致ならケースページへ直行 |
| IPアドレス・ドメイン・URL・接続先 | `45.66.228.114`、`ftp.vilimorin.com`、`202.95.8.27:6666` |
| マルウェアファミリ名・別名 | `AgentTesla`、`Amatera`（`ACRStealer／Amatera` の別名） |
| キャンペーン相関候補 | `correlated-efimer-…` |
| ファイル名・タグ・コレクション・キャンペーン種別 | ケースの検索用文字列に含まれる値 |

ダッシュボード上の検索窓:

- 統計カードの直下にあり、**入力すると下の内容がその場でリアルタイムに絞り込まれます**（画面遷移しません）。2文字以上で作動し、消すか `Esc` で通常のダッシュボードへ戻ります。
- 結果は検索ページと同じ区分（ファミリ／IOC・通信先／検体ケース／キャンペーン候補）で、各区分の上位12件を表示します。`Enter` または「検索ページで詳しく見る」で全件表示へ移動します。

挙動:

- 入力中はヘッダーに候補が出ます（ファミリ／IOC／検体／キャンペーンを種別付きで表示）。Enter で `#/search` の結果ページへ移動します。
- 結果は **マルウェアファミリ / IOC・通信先 / 検体ケース / キャンペーン相関候補** に分けて表示します。IOCは同じ値を1行に畳み、観測ケース数と観測元ファミリを出します。
- レポートから貼り付けた無害化表記（`1.2.3[.]4`、`hxxp://`、`[at]`）はそのまま検索できます。内部で元の表記へ戻して照合します。
- 一致は「完全一致 → 前方一致 → 部分一致」の順に並べます。

用途が絞れている場合は、従来どおり `#/cases`（ケース絞り込み）と `#/iocs`（IOC表と一括コピー）も使えます。

## 参照しているサービス

UIのフッターに、解析で参照している外部サービスのクレジットを常時表示します（全画面共通。ポータルへiframe埋め込みしたときも表示されるよう、`embed_css` ではヘッダーだけを隠しています）。

| 区分 | サービス |
|---|---|
| 解析対象検体の取得 | MalwareBazaar（abuse.ch）、VX-Underground |
| サンドボックス・照会 | VirusTotal（file behaviours の挙動・ハッシュ照会）、Hatching Triage（process／network 証跡）、ANY.RUN、Shodan（受動的なインフラ調査） |
| 公開情報・知識ベース | MITRE ATT&CK、JPCERT/CC、および各セキュリティベンダー・研究者の公開レポート |
| インフラ位置・地図 | MaxMind GeoLite2 City / ASN（地図に出すC2 IPの概略位置とAS。対象C2へは接続しない）、ipwho.is（ClickFix基盤調査のIP pivot）、Natural Earth（世界地図の輪郭 / public domain）、Tor Project（.onion endpointの観測経路）<br>`This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com.` |

個別の出典は各ケース／ファミリの `OSINT.md` に記載しています。掲載は `ui/index.html` のフッター（`.credits`）を直接編集します。参照先を増減した場合はここも更新してください。

## C2稼働状況と世界地図

地図クリック・検索窓・「応答なしを表示」トグルは同じ絞り込み状態を共有し、掛け合わせで効きます。効いている条件はテーブル直上のフィルタバーにチップで並び、チップごとの `✕` で個別に解除できます（地図の余白クリックや「表示をリセット」でも解除されます）。

`#/c2` は `monitor_recent_c2.py` の観測結果を表示します。**到達性**と**C2 applicationが稼働している確度**は生成側でもUI側でも混ぜず、`到達` / `C2稼働` / `手法上限` の3本を別々に出します。TCP接続だけで到達しても、C2稼働確度は 0.25 を超えません。

地図に必要な緯度経度・国・ASは、C2監視パイプラインが `monitoring-results.json` へ埋め込む **MaxMind GeoLite2 City / ASN** だけを読みます（`analysis-framework/common/maxmind_c2_enrichment.py`、手順は `analysis-framework/common/MAXMIND-C2-ENRICHMENT.md`）。geoの出所を1本に絞っているのは、第三者APIと併用すると同一IPで国が食い違う（例: 同じIPが `CN Beijing` と `SG`）ためです。

GeoLite2はIPインフラの概略位置であり、C2稼働・攻撃者の所在地・個人や住所の特定には使えません。UIにもその旨を併記しています。

GeoLite2のライセンスが要求する帰属表示（`This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com.`）は、UIフッターの「参照しているサービス」に常時表示しています。

世界地図の輪郭は Natural Earth 110m（public domain）を等距円筒で投影して `ui/worldmap.js` に同梱しています（約120KiB、176か国）。外部CDNは読みません。地図とプロット点には同じ投影を掛けるので、点と国境は必ず一致します。再生成は次のとおりです。

```bash
python3 ui/build_world_map.py    # 既定でNatural Earthの110m countriesを取得して再生成
python3 ui/build_world_map.py --check
```

`worldmap.js` は取り込み済みの静的アセットなので、デプロイのたびに再生成はしません（生成には外部取得が必要なため、CIの整合性チェックには含めていません）。


## グラフ調査は横断ポータルへ集約

グラフでのpivot調査は、横断ポータル [research_bench](https://proshiba.github.io/research_bench/) の**ワークベンチ**に集約しました。同じ機能をこのUIにも持たせる意味がないため、`ui/graph.js` と `#/graph` は削除しています。

このUIの各所（ケースページ・ファミリページ・キャンペーン相関詳細の「ポータルのグラフで調査」、IOC検索の各行とC2チップの「⊕」）は、ポータルの検索ルートへ値を渡します。

```text
https://proshiba.github.io/research_bench/#/search/<値>
  → 検索結果の「グラフで開く」からワークベンチのグラフへ
```

ポータルのワークベンチ（`#/workbench`）はURL引数を取らないため、公開ルートである検索を経由します。リンクには `target="_top"` を付けており、ポータルのiframe内から押してもポータルが入れ子にならず最上位で遷移します。

`meta.json` からは `_graph` のdeep linkと `graph` capabilityを外しています。これによりポータルの `graphLink()` はこのアプリへグラフリンクを作らなくなります。

## データソースと生成規則

`ui/data.js` は `generate_ui_data.py` が以下から生成します。

- `analysis-results/catalog/cases.json`: 全ケースの正本一覧(ファミリ・版・格納パス)。固定レイアウトの全caseと完全一致する必要があります。不足・余剰・family／版／pathの不一致が1件でもあれば生成を停止し、暗黙補完は行いません
- 各ケースディレクトリの `metadata.json` / `features.json` / `iocs.json` / `IOC-LIST.md` / `README.md` / `rules/`
- `analysis-results/malware/<family>/` の `README.md`・`OSINT.md`・`TECHNICAL-ANALYSIS.md`・`VERSIONS.md`・`CAMPAIGNS.md`・`BEHAVIOR-C2.md` と `rules/`(YARA/Sigma)
- `analysis_history.yaml`: 検体SHA-256ごとの解析履歴(解析日、解析レベル、campaign type、一致パターン、主要C2)
- `analysis-results/research/campaigns/correlated-*/campaigns.json`（最新版）: `intelligence/` 定期調査が参照するcampaign相関候補とcase別label
- `analysis-results/research/c2-monitoring/<YYYY-MM-DD>/`: `monitoring-results.json`（endpoint毎の観測と到達／C2稼働confidence）と `ip-geo.json`（解決IPの国・都市・緯度経度・ASN）。日付ディレクトリを新しい順に読み、endpoint(host:port)単位で最新観測と全ランの履歴を持たせます
- `analysis-results/clickfix/<domain>/cases/<YYYYMMDD-...>/infrastructure.json`: 日付別caseのAレコードから、ドメインの解決IP推移を組み立てます
- `analysis-results/catalog/code-similarity.json`: 意味トークン列SHA-256が完全一致する関数groupだけをケース間リンクへ集約（SimHash近似は含めない）。21ケース以上に広がるgroupはlibrary/compiler由来の可能性が高いため除外

サイズ抑制のため、ケース単位の `STATIC-LOGIC.md` と `FEATURES.md` は全文を埋め込まず、ケースページの「成果物ファイル」からのリンク参照とします(挙動・特徴は `features.json` 由来の構造化データで表示します)。

## 運用上の注意

- `ui/data.js` は生成物です。直接編集せず、元の解析成果物を更新してから再生成してください。
- 表示されるIOC・YARA・Sigmaは検知仮説であり、リポジトリ本体の方針どおり、IP・ドメイン・ファイル名の単独条件ではなく役割・確度・根拠と組み合わせて利用してください。
- UIは外部ネットワークへ一切アクセスしません。フッターの参照元リンク、ファミリ文書内の出典リンク、ポータルへのpivotリンクは、利用者が明示的に押したときだけ遷移します(自動取得・ビーコンの類はありません)。
