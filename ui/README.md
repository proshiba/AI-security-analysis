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
| ダッシュボード (`#/`) | ケース数・ファミリ数・IOC数・ルール数の統計、ケース数上位ファミリ、最近の解析履歴 |
| ファミリ一覧 (`#/families`) | 全マルウェアファミリのカード一覧 |
| ケース検索 (`#/cases`) | SHA-256、ファミリ、キャンペーン種別、コレクション、C2有無、IOC値、ファイル名の横断検索 |
| IOC検索 (`#/iocs`) | 全ケースの `IOC-LIST.md` を集約したIOC表。種別フィルタと値の一括コピー、各行からグラフ調査へのpivot（⊕） |
| キャンペーン相関 (`#/intel`) | intelligence調査のcampaign相関候補一覧・詳細（共有指標、相関ケース、ルール、制約） |
| グラフ調査 (`#/graph`) | Maltego風のインタラクティブグラフでのpivot調査。詳細は下記 |
| ファミリ別ページ (`#/family/<key>`) | ケース一覧、YARA/Sigmaルール、概要・OSINT・技術解析・版情報などの文書タブ |
| ケース別ページ (`#/case/<sha256>`) | 判定・検体メタデータ、C2、挙動・機能、検体特徴、IOC表、検知ルール、解析履歴タイムライン、ケースREADME、成果物ファイルへのリンク |

ヘッダーの検索ボックスに完全なSHA-256を入れると該当ケースへ直接移動します。`#/case/<SHA-256先頭一致>` でも一意に決まればリダイレクトします。

## グラフ調査（pivot調査）

検体ハッシュ・C2・IOCの関連を、力学レイアウトのインタラクティブグラフ（`ui/graph.js`、外部ライブラリ不使用）で辿れます。

- **ノード種別**: 検体ケース、ファミリ、キャンペーン、campaign相関候補、コレクション、IPアドレス、接続先（host:port）、ドメイン、URL、ファイルハッシュ、その他IOC。`ip:port` や URL は自動でホストノード（IP/ドメイン）に分解して接続します。
- **相関インテリジェンス**: campaign相関候補ノードは相関ケースと共有指標を接続します。コード完全一致リンク（下記）はケース間の「コード類似 n関数」エッジとして表示されます。
- **起点の指定**: ケースページ・ファミリページの「グラフで調査」ボタン、IOC検索の各行の「⊕」、グラフ画面上部の検索ボックス（SHA-256前方一致・IP・ドメイン・ファミリ名などで追加）。
- **展開（pivot）**: ノードのダブルクリックで全関連を展開。右クリックまたは右サイドバーから「IPアドレスだけ展開」のように種別を絞った展開ができます。ノード右上の緑バッジは未展開の関連ノード数です。1回の展開は40件までで、超過分は種別を絞って展開します。
- **操作**: ノードドラッグ（移動して位置固定）、背景ドラッグ（パン）、ホイール（ズーム）、クリック（選択して詳細表示）、Delete（選択ノード削除）、右クリック（展開・削除・固定解除・「このノード以外を削除」）。
- **その他**: 全体表示・再レイアウト・物理ON/OFF・PNG保存・クリア。グラフ内容は `localStorage` に自動保存され、次回 `#/graph` を開いたときに復元されます。

例: ケースページから「グラフで調査」→ C2 の `ip:port` ノードを展開 → 同じIPを共有する別ファミリのケースが現れる → そのケースを展開してファイルIOCやキャンペーンの重なりを確認する、という流れで共有インフラのpivot調査ができます。

## データソースと生成規則

`ui/data.js` は `generate_ui_data.py` が以下から生成します。

- `analysis-results/catalog/cases.json`: 全ケースの正本一覧(ファミリ・版・格納パス)。catalog再生成が解析より遅れている期間の新規caseは、`analysis-results/malware/**/cases/<sha256>/` のディレクトリ走査で補完します
- 各ケースディレクトリの `metadata.json` / `features.json` / `iocs.json` / `IOC-LIST.md` / `README.md` / `rules/`
- `analysis-results/malware/<family>/` の `README.md`・`OSINT.md`・`TECHNICAL-ANALYSIS.md`・`VERSIONS.md`・`CAMPAIGNS.md`・`BEHAVIOR-C2.md` と `rules/`(YARA/Sigma)
- `analysis_history.yaml`: 検体SHA-256ごとの解析履歴(解析日、解析レベル、campaign type、一致パターン、主要C2)
- `analysis-results/research/campaigns/correlated-*/campaigns.json`（最新版）: `intelligence/` 定期調査が参照するcampaign相関候補とcase別label
- `analysis-results/catalog/code-similarity.json`: 意味トークン列SHA-256が完全一致する関数groupだけをケース間リンクへ集約（SimHash近似は含めない）。21ケース以上に広がるgroupはlibrary/compiler由来の可能性が高いため除外

サイズ抑制のため、ケース単位の `STATIC-LOGIC.md` と `FEATURES.md` は全文を埋め込まず、ケースページの「成果物ファイル」からのリンク参照とします(挙動・特徴は `features.json` 由来の構造化データで表示します)。

## 運用上の注意

- `ui/data.js` は生成物です。直接編集せず、元の解析成果物を更新してから再生成してください。
- 表示されるIOC・YARA・Sigmaは検知仮説であり、リポジトリ本体の方針どおり、IP・ドメイン・ファイル名の単独条件ではなく役割・確度・根拠と組み合わせて利用してください。
- UIは外部ネットワークへ一切アクセスしません(ファミリ文書内の出典リンクを利用者が明示的に開く場合を除く)。
