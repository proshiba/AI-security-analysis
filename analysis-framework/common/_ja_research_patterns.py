"""研究・監査文書に残る混在英語を日本語化する限定変換規則。"""

from __future__ import annotations

import re


_EXACT_TRANSLATIONS = {
    "2. UTF-8 BOM、UTF-16LE/BE BOM、NUL分布によるUTF-16推定を統一する。":
        "2. UTF-8 のバイト順マーク、UTF-16 LE/BE のバイト順マーク、ヌルバイト分布による UTF-16 推定を統一する。",
    "8. 高entropyだけでpackingと決めず、imports、entry point section、raw/virtual section形状、UPX/NSIS等のmarkerを併用する。仮想化形状は別分類する。":
        "8. 高エントロピーだけでパッキングと決めず、インポート、エントリポイントが属するセクション、ファイル上と仮想メモリ上のセクション形状、UPX・NSIS などのマーカーを併用する。仮想化形状は別分類する。",
    "### VenomRAT": "### VenomRAT の再評価",
    "既存の .NET Bitmap列走査も再検証した。`7215...` から `7a66395f...`（68,096 bytes）、`6518...` と `165b...` から同一の `3aa8ce5d...`（33,792 bytes）を復元し、いずれも追加packingなしと判定した。":
        "既存の .NET ビットマップ列走査も再検証した。`7215...` から `7a66395f...`（68,096 バイト）、`6518...` と `165b...` から同一の `3aa8ce5d...`（33,792 バイト）を復元し、いずれも追加のパッキングなしと判定した。",
    "- Formbook の .NET Bitmap loaderから `7a09d4c71af5d34d449fc0ba91c8993492828bc5d6a1a3300c3f27df63c56e28`（66,560 bytes、x86 .NET、not packed）を復元した。":
        "- Formbook の .NET ビットマップローダーから `7a09d4c71af5d34d449fc0ba91c8993492828bc5d6a1a3300c3f27df63c56e28`（66,560 バイト、x86 .NET、パッキングなし）を復元した。",
    "- RemusStealer の2件は、自己解凍コンテナ → CAB → AutoIt A3X → RC4 → LZNT1を通し、同一の終端PE `a86f0adedfb993195509aa2923204bdccbf0b9e4d59d0f99636de3b0db5b4668`（222,208 bytes、x64、not packed）を復元した。":
        "- RemusStealer の2件は、自己解凍コンテナ → CAB → AutoIt A3X → RC4 → LZNT1 を通し、同一の終端 PE `a86f0adedfb993195509aa2923204bdccbf0b9e4d59d0f99636de3b0db5b4668`（222,208 バイト、x64、パッキングなし）を復元した。",
    "- LummaStealer はNSIS/Jadoo分割manifestのoffset、size、連続性を検証して再構成した。":
        "- LummaStealer は NSIS/Jadoo 分割マニフェストのオフセット、サイズ、連続性を検証して再構成した。",
    "### RemusStealer: `5e815731...`": "### RemusStealer（`5e815731...`）の再評価",
    "- x64 PE、imports 0、`.rdata` 228,352 bytes・entropy 7.9942、entry pointは高entropy領域。":
        "- x64 PE、インポート数0、`.rdata` は228,352バイトでエントロピー7.9942、エントリポイントは高エントロピー領域にある。",
    "- entry側でAPIをhash解決し、約 `0x36400` bytesのRWX領域を確保する。":
        "- エントリ側で API をハッシュ解決し、約 `0x36400` バイトの読み書き・実行可能領域を確保する。",
    "- Ghidraで復号/メモリローダー候補 `0x140001730` を追跡したが、巨大な独自state machineであり、単純な定数鍵や既知packerではない。":
        "- Ghidra で復号・メモリローダー候補 `0x140001730` を追跡したが、巨大な独自状態機械であり、単純な定数鍵や既知のパッカーではない。",
    "- blocker: `native_control_flow_obfuscation`。安全方針上、検体実行、loader stub実行、プロセスメモリdump、CPU emulationは行っていない。":
        "- 未解決要因: `native_control_flow_obfuscation`。安全方針上、検体の実行、ローダースタブの実行、プロセスメモリのダンプ、CPU エミュレーションは行っていない。",
    "### ValleyRAT: 3件": "### ValleyRAT 3件の再評価",
    "3件は同形状のx64 protectorで、importsは `KERNEL32!GetLastError` だけ、通常sectionはraw size 0、巨大なランダム名RX sectionにentry pointと高entropy codeがある。Ghidraで代表 `ad4a...` を明示的program selector付きで解析したところ、overlapping instruction、opaque predicate、内部thunk、`rdtsc`、stack-state操作を持つ仮想化/制御フロー保護を確認した。blockerは `native_control_flow_obfuscation` である。":
        "3件は同じ形状の x64 プロテクターで、インポートは `KERNEL32!GetLastError` だけ、通常のセクションはファイル上のサイズが0で、巨大なランダム名の読み取り・実行可能セクションにエントリポイントと高エントロピーのコードがある。Ghidra で代表検体 `ad4a...` を明示的なプログラム指定付きで解析したところ、命令の重なり、不透明な条件分岐、内部サンク、`rdtsc`、スタック状態の操作を持つ仮想化・制御フロー保護を確認した。未解決要因は `native_control_flow_obfuscation` である。",
    "### RemcosRAT: `78b21599...`": "### RemcosRAT（`78b21599...`）の再評価",
    "- NSIS decompilationからワードXOR鍵 `0x17d68b37` と1,024-byte command stream `b2d8fcd1...` を復元した。":
        "- NSIS の逆コンパイル結果からワード単位の XOR 鍵 `0x17d68b37` と1,024バイトのコマンド列 `b2d8fcd1...` を復元した。",
    "- System callsから `Flagskibene` のoffset 6,800に1,482-byte decoder、offset 8,282に後段があることを確定した。":
        "- システムコールから `Flagskibene` のオフセット6,800に1,482バイトのデコーダー、オフセット8,282に後段があることを確定した。",
    "- x64定数伝播によりdword XOR鍵 `0xe7c94882`、length 435,824、step 4を特定し、中間loader `e9ed0be544b08189ceca2ec8e6ae8f74d62335ed006f0b207fb211df6bbdcb3a` を復元した。":
        "- x64 の定数伝播により32ビット値の XOR 鍵 `0xe7c94882`、長さ435,824、増分4を特定し、中間ローダー `e9ed0be544b08189ceca2ec8e6ae8f74d62335ed006f0b207fb211df6bbdcb3a` を復元した。",
    "1. magicとファイル名を分離して判定する。RAR5、NSIS、UTF-16、OLE、Mach-Oを見落とさない。":
        "1. マジック値とファイル名を分離して判定する。RAR5、NSIS、UTF-16、OLE、Mach-O を見落とさない。",
    "2. archive inventory、member上限、展開総量、path traversal、symlink/reparse pointを確認する。":
        "2. アーカイブ内の一覧、メンバー数の上限、展開総量、パストラバーサル、シンボリックリンク・再解析ポイントを確認する。",
    "3. PEはheader、section bounds、imports、entry point、overlay、resourceを確認する。entropyだけでpackingを断定しない。":
        "3. PE はヘッダー、セクション境界、インポート、エントリポイント、オーバーレイ、リソースを確認する。エントロピーだけでパッキングを断定しない。",
    "- `unpackers/tests`: 21 tests passed。": "- `unpackers/tests`: 21件のテストに合格。",
    "- Ruff: unpackers全体でpass。": "- Ruff によるアンパッカー全体の検査に合格。",
    "- 解析-framework、extractors、unpackers の関連suite合計84 tests passed。":
        "- analysis-framework、extractors、unpackers の関連テストスイートは合計84件に合格。",
    "# Security news analysis: 2026-04-01":
        "# 2026年4月1日のセキュリティニュース解析",
    "| 1 | 日本語賞与通知を装う ValleyRAT | 配布チェーン confirmed、最終設定 unverified | [ケース解析](../../../malware/valleyrat/versions/unknown/cases/f543dcf4f178e464c7b4dc24b463272417d8ada2a7d3a832e177f37e64f10cbd/README.md)、誤帰属を避ける検出器改修 |":
        "| 1 | 日本語賞与通知を装う ValleyRAT | 配布チェーンを確認済み、最終設定は未検証 | [ケース解析](../../../malware/valleyrat/versions/unknown/cases/f543dcf4f178e464c7b4dc24b463272417d8ada2a7d3a832e177f37e64f10cbd/README.md)、誤帰属を避ける検出器改修 |",
    "| 2 | Trivy/TeamPCP と Cisco 開発環境侵害報道 | Trivy confirmed、Cisco範囲は報道ベース | [供給網解析](../../supply-chain/trivy-teampcp-2026/README.md)、オフライン監査器 |":
        "| 2 | Trivy/TeamPCP とシスコ開発環境の侵害報道 | Trivy は確認済み、シスコの範囲は報道情報のみ | [供給網解析](../../supply-chain/trivy-teampcp-2026/README.md)、オフライン監査器 |",
    "| 3 | Uranium Finance 約5,300万ドル窃取 | 起訴内容 confirmed、マルウェアなし | スマートコントラクト悪用として整理。検体解析対象外 |":
        "| 3 | ウラニウム・ファイナンスから約5,300万ドル窃取 | 起訴内容を確認済み、マルウェアなし | スマートコントラクト悪用として整理。検体解析対象外 |",
    "| 5 | NetScaler CVE-2026-3055 | 脆弱性・悪用 confirmed | [防御的評価](../../vulnerabilities/cve-2026-3055/README.md)。PoC再現は行わない |":
        "| 5 | ネットスケーラー CVE-2026-3055 | 脆弱性と悪用を確認済み | [防御的評価](../../vulnerabilities/cve-2026-3055/README.md)。概念実証コードの再現は行わない |",
    "| 6 | CareCloud EHR環境侵害 | SEC提出内容 confirmed | 公開IOC・マルウェアなし。1/6環境が約8時間影響 |":
        "| 6 | ケアクラウドの電子健康記録環境侵害 | 米証券取引委員会への提出内容を確認済み | 公開 IOC・マルウェアなし。6環境中1環境が約8時間影響 |",
    "| 7 | axios npm供給網侵害 | setup.jsを静的に confirmed | [実検体解析](../../supply-chain/npm/axios-plain-crypto-js-2026/cases/e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09/README.md)、復号器・監査器 |":
        "| 7 | axios npm供給網侵害 | setup.jsを静的に確認済み | [実検体解析](../../supply-chain/npm/axios-plain-crypto-js-2026/cases/e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09/README.md)、復号器・監査器 |",
    "| 8 | Silver Foxによる AtlasCross/Atlas RAT配布 | 公開技術解析で confirmed | [キャンペーン解析](../../campaigns/atlascross/silver-fox-vpn-2026/README.md)、設定復号器（合成fixtureで検証） |":
        "| 8 | シルバーフォックスによるアトラスクロス／アトラス遠隔操作型トロイの配布 | 公開技術解析で確認済み | [キャンペーン解析](../../campaigns/atlascross/silver-fox-vpn-2026/README.md)、設定復号器（合成した検証用データで確認） |",
    "## 3. Uranium Finance": "## 3. ウラニウム・ファイナンス",
    "## 6. CareCloud": "## 6. ケアクラウド",
    "2026-03-27のSEC Form 8-Kでは、3月16日にCareCloud Healthの6つのEHR環境のうち1つが不正な第三者アクセスを受け、機能とデータアクセスが約8時間部分的に影響した。提出時点でアクセス／持ち出しの範囲を調査中としており、攻撃者、初期侵入、マルウェア、C2は非公開である。EHR監査ログ、特権操作、異常エクスポート、同時間帯のIdP／VPN／EDR相関が優先で、公開情報だけからルールを狭く固定するのは危険である。":
        "2026年3月27日の米証券取引委員会向け様式8-Kでは、3月16日にケアクラウド・ヘルスの6つの電子健康記録環境のうち1つが不正な第三者アクセスを受け、機能とデータアクセスが約8時間部分的に影響した。提出時点でアクセスと持ち出しの範囲を調査中としており、攻撃者、初期侵入、マルウェア、C2 は非公開である。電子健康記録の監査ログ、特権操作、異常なエクスポート、同時間帯の認証基盤・仮想私設網・端末検知応答の相関を優先すべきであり、公開情報だけからルールを狭く固定するのは危険である。",
    "## Sources": "## 情報源",
    "- Source memo: https://github.com/proshiba/tech-memo/blob/main/daily-news/news/2026_04-06/20260401.md":
        "- 元資料: https://github.com/proshiba/tech-memo/blob/main/daily-news/news/2026_04-06/20260401.md",
    "- ITOCHU Cyber & Intelligence ValleyRAT analysis: https://blog.itochuci.co.jp/entry/2026/04/03/133000":
        "- 伊藤忠サイバー＆インテリジェンスによる ValleyRAT 解析: https://blog.itochuci.co.jp/entry/2026/04/03/133000",
    "- Aqua Trivy advisory: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23":
        "- アクアによるトリビーの注意喚起: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23",
    "- U.S. DOJ Uranium Finance release: https://www.justice.gov/usao-sdny/pr/maryland-man-charged-defrauding-crypto-exchange-over-50-million-hacks":
        "- U.S. 司法省によるウラニウム・ファイナンス事件の発表: https://www.justice.gov/usao-sdny/pr/maryland-man-charged-defrauding-crypto-exchange-over-50-million-hacks",
    "- Dutch government incident retrospective: https://www.rijksoverheid.nl/actueel/nieuws/2026/06/18/terugblik-cyberincident":
        "- オランダ政府によるインシデントの振り返り: https://www.rijksoverheid.nl/actueel/nieuws/2026/06/18/terugblik-cyberincident",
    "- Citrix bulletin: https://support.citrix.com/external/article/CTX696300/netscaler-adc-and-netscaler-gateway-secu.html":
        "- シトリックスの告知: https://support.citrix.com/external/article/CTX696300/netscaler-adc-and-netscaler-gateway-secu.html",
    "- CareCloud SEC Form 8-K: https://www.sec.gov/Archives/edgar/data/1582982/000149315226013239/form8-k.htm":
        "- ケアクラウドの米証券取引委員会向け様式8-K: https://www.sec.gov/Archives/edgar/data/1582982/000149315226013239/form8-k.htm",
    "- axios post-mortem: https://github.com/axios/axios/issues/10636":
        "- axios の事後検証: https://github.com/axios/axios/issues/10636",
    "- StepSecurity axios analysis: https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan":
        "- ステップセキュリティによる axios 解析: https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan",
    "- Hexastrike AtlasCross analysis: https://hexastrike.com/resources/blog/threat-intelligence/trust-the-tunnel-get-the-trojan-silver-fox-delivers-atlas-rat-via-weaponized-vpn-installers/":
        "- ヘキサストライクによるアトラスクロス解析: https://hexastrike.com/resources/blog/threat-intelligence/trust-the-tunnel-get-the-trojan-silver-fox-delivers-atlas-rat-via-weaponized-vpn-installers/",
    "- COTA first report: https://www.kabutec.jp/pdf/202603/140120260330592911.pdf":
        "- コタ株式会社の第1報: https://www.kabutec.jp/pdf/202603/140120260330592911.pdf",
    "No malware was executed and no live infrastructure was contacted during this work.":
        "本作業では、マルウェアの実行および稼働中インフラへの接続を行っていない。",
    "# NetScaler CVE-2026-3055 defensive assessment":
        "# ネットスケーラー CVE-2026-3055 の防御的評価",
    "Citrix describes CVE-2026-3055 as insufficient input validation leading to an out-of-bounds memory read (CWE-125), CVSS v4 9.3. The precondition is a customer-managed NetScaler ADC/Gateway configured as a SAML IdP. CISA added it to KEV on 2026-03-30.":
        "シトリックスは脆弱性 CVE-2026-3055 を、入力検証不足により境界外メモリ読み取りが生じる脆弱性タイプ（CWE-125）と説明し、共通脆弱性評価システム第4版で9.3としている。前提条件は、顧客管理のネットスケーラー配信制御装置またはゲートウェイが、セキュリティアサーションマークアップ言語による識別情報提供者として構成されていることである。米国サイバーセキュリティ・インフラ安全保障庁は2026年3月30日、既知悪用脆弱性一覧に追加した。",
    "Affected versions are 14.1 before 14.1-60.58, 13.1 before 13.1-62.23, and 13.1-FIPS/NDcPP before 13.1-37.262. Check configuration for `add authentication samlIdPProfile .*` and upgrade to a fixed supported build.":
        "影響を受けるのは14.1-60.58未満の14.1、13.1-62.23未満の13.1、13.1-37.262未満の13.1-FIPS/NDcPPである。`add authentication samlIdPProfile .*` に一致する構成を確認し、修正済みでサポート対象のビルドへ更新する。",
    "## Hunting guidance": "## 調査指針",
    "- inventory builds and SAML IdP profiles first; appliances without this configuration do not meet the published precondition;":
        "- 最初にビルドと SAML 識別情報提供者プロファイルを棚卸しする。この構成がない装置は、公開された前提条件を満たさない。",
    "- preserve ns.log, HTTP access, authentication, crash/core, configuration and administrative audit data before reboot/upgrade;":
        "- 再起動または更新の前に、ns.log、HTTP アクセス、認証、クラッシュとコア、構成、管理監査の各データを保全する。",
    "- look for anomalous requests to SAML IdP endpoints, worker crashes/restarts, unusual response sizes, and follow-on session/config changes;":
        "- SAML 識別情報提供者の接続先への異常要求、ワーカープロセスのクラッシュや再起動、異常な応答サイズ、その後のセッションや構成の変更を調査する。",
    "- an error/crash alone is high-noise. Require version, SAML IdP exposure, request shape and timing correlation.":
        "- エラーまたはクラッシュ単独では雑音が多い。バージョン、SAML 識別情報提供者の公開状況、要求の形状、時刻の相関を併せて確認する。",
    "This repository does not include exploit code or an active validation probe. A successful memory overread can expose data, but the public CVE description alone does not prove code execution or a specific malware deployment.":
        "本リポジトリには、悪用コードや能動的な検証プローブを含めていない。メモリの境界外読み取りに成功するとデータが露出し得るが、公開された脆弱性説明だけではコード実行や特定マルウェアの配備を証明できない。",
    "Sources: https://support.citrix.com/external/article/CTX696300/netscaler-adc-and-netscaler-gateway-secu.html and https://nvd.nist.gov/vuln/detail/CVE-2026-3055":
        "情報源: https://support.citrix.com/external/article/CTX696300/netscaler-adc-and-netscaler-gateway-secu.html および https://nvd.nist.gov/vuln/detail/CVE-2026-3055",
    "2026-07-17に、公開成果物、宣言的定義、runner／compiler、classifier、extractor、unpacker、report generator、通信機能を持つhelper、test、文書、難解析80件のinventoryを横断監査しました。検体と復元layerは不活性byte列としてだけ扱い、実行、CPU／CILエミュレーション、抽出インフラへの接続は行っていません。":
        "2026年7月17日に、公開成果物、宣言的定義、実行器とコンパイラ、分類器、抽出器、アンパッカー、レポート生成器、通信機能を持つ補助ツール、テスト、文書、難解析80件の一覧を横断監査しました。検体と復元レイヤーは不活性なバイト列としてだけ扱い、実行、中央処理装置または共通中間言語のエミュレーション、抽出インフラへの接続は行っていません。",
    "この表は詳細監査を記録した時点の状態です。その後、固定レイアウトへの全面移行、版根拠の機械可読化、OSINT文書生成、全Markdownの日本語化、collection index、公開JSON境界の追加検証も実施しました。後続変更によって解消した項目は、最終履歴とtest結果を優先してください。":
        "この表は詳細監査を記録した時点の状態です。その後、固定レイアウトへの全面移行、版根拠の機械可読化、公開情報文書の生成、全 Markdown 文書の日本語化、コレクション索引、公開 JSON 境界の追加検証も実施しました。後続変更によって解消した項目は、最終履歴とテスト結果を優先してください。",
    "## このpassで追加解析した主要項目":
        "## 今回の監査で追加解析した主要項目",
    "- RemcosのNSIS chainは、7-Zip 26.xで失われたsynthetic scriptに依存しない、境界とXOR構造を照合する静的fallbackを追加しました。":
        "- Remcos の NSIS チェーンには、7-Zip 26.x で失われた合成スクリプトに依存せず、境界と XOR 構造を照合する静的な予備処理を追加しました。",
    "- StealCの未解決call-EAXをghidra-mcpで明示的program selector付きで逆コンパイルし、2件をdynamic API resolverの戻り値、13件を通常IAT thunkと確認しました。残る課題は2,929,408 byte overlayのdecoder同定です。":
        "- StealC の未解決な EAX 経由呼び出しを ghidra-mcp で明示的なプログラム指定付きで逆コンパイルし、2件を動的 API 解決器の戻り値、13件を通常の IAT サンクと確認しました。残る課題は2,929,408バイトのオーバーレイに対するデコーダーの同定です。",
    "- RedLineのnative control-flow flattening候補はloop／joinでありdispatcherではないことをCFGで確認し、誤検出gateを修正しました。":
        "- RedLine のネイティブ制御フロー平坦化候補はループと合流点であり、ディスパッチャーではないことを制御フローグラフで確認し、誤検出防止条件を修正しました。",
    "- njRATのmanaged switchはapplication command dispatchとの混同を除去しつつ、根拠が不足する候補を安易に除外しないよう `inconclusive` を維持しました。":
        "- njRAT のマネージド分岐は、アプリケーションのコマンド振り分けとの混同を除去しつつ、根拠が不足する候補を安易に除外しないよう `inconclusive` を維持しました。",
    "- hard-case 80件は155 layerを静的解析し、budget超過0、期待childの未解析0を確認しました。":
        "- 難解析80件は155レイヤーを静的解析し、予算超過0件、想定した子レイヤーの未解析0件を確認しました。",
    "| `579085581348296ae88419296edc6a8e91acf4463c7994112b5c3f7f3653710e` | UTF-16 JS → 数値配列XOR → PowerShell → 環境変数366個 → Unicode -19968 | `4246bf9121476cc6fb8d2f69c6263a7b4d31a331bd02dd9a7603e6200fb9725b` | 361,984 | x64 .NET / not packed |":
        "| `579085581348296ae88419296edc6a8e91acf4463c7994112b5c3f7f3653710e` | UTF-16スクリプト → 数値配列の排他的論理和 → PowerShell → 環境変数366個 → Unicode値から19968減算 | `4246bf9121476cc6fb8d2f69c6263a7b4d31a331bd02dd9a7603e6200fb9725b` | 361,984 | x64 .NET／パッキングなし |",
    "| `48b59f27da42cfe2d3b806a1c71cc8d8fce0441121a17cd8c1b30bf5e35ea776` | RAR5 → 上記JS → 同じPowerShell/PE | `4246bf9121476cc6fb8d2f69c6263a7b4d31a331bd02dd9a7603e6200fb9725b` | 361,984 | x64 .NET / not packed |":
        "| `48b59f27da42cfe2d3b806a1c71cc8d8fce0441121a17cd8c1b30bf5e35ea776` | RAR5 → 上記スクリプト → 同じPowerShell／PE | `4246bf9121476cc6fb8d2f69c6263a7b4d31a331bd02dd9a7603e6200fb9725b` | 361,984 | x64 .NET／パッキングなし |",
    "| `d7de7d851061a99e6f2ca256aba5badf90778f566fc528db6396a4180901ac26` | UTF-16 JS → 反復減算 → PowerShell → 環境変数80個 → AES-CBC → GZip | `16109f93bcddf8dec5e21057f35b3da437d94976f503f45b217232c26b65515e` | 237,568 | x64 .NET / not packed |":
        "| `d7de7d851061a99e6f2ca256aba5badf90778f566fc528db6396a4180901ac26` | UTF-16スクリプト → 反復減算 → PowerShell → 環境変数80個 → AES-CBC復号 → GZip展開 | `16109f93bcddf8dec5e21057f35b3da437d94976f503f45b217232c26b65515e` | 237,568 | x64 .NET／パッキングなし |",
    "- `generate_stealer_reports.py` と `generate_family_reports.py` が、次回実行時にcollection配下へcase本体を再作成する経路を修正しました。共通の `result_publication.py` から固定case pathを解決し、case metadata、catalog、collection membershipをstale検査付きで同期します。既存catalogがあっても任意の誤配置pathは許可しません。":
        "- `generate_stealer_reports.py` と `generate_family_reports.py` が、次回実行時にコレクション配下へケース本体を再作成する経路を修正しました。共通の `result_publication.py` から固定ケースパスを解決し、ケースのメタデータ、カタログ、コレクション所属情報を古さの検査付きで同期します。既存カタログがあっても任意の誤配置パスは許可しません。",
    "- 移行後の `normalize_result_layout.py` が既存collectionを再集計せず0件と表示する欠陥を修正しました。case metadataとmanifestを相互照合して4 collection／408 membershipを再検証し、不一致をwrite前に拒否します。同一metadata／catalog／manifestは再作成せず、checksum manifestも内容が変わった場合だけ再生成します。":
        "- 移行後の `normalize_result_layout.py` が既存コレクションを再集計せず0件と表示する欠陥を修正しました。ケースのメタデータとマニフェストを相互照合して4コレクション、408件の所属情報を再検証し、不一致は書き込み前に拒否します。同一のメタデータ、カタログ、マニフェストは再作成せず、チェックサムマニフェストも内容が変わった場合だけ再生成します。",
    "- OSINT hash補強は既定でnetwork無効とし、明示的な `--allow-network` がある場合だけ外部providerを利用します。固定collectionへ出力する場合はcatalogでcaseを解決し、collection manifest、membership、family sourceを検証してcanonical相対linkを生成します。":
        "- 公開情報によるハッシュ補強は既定でネットワークを無効とし、明示的な `--allow-network` がある場合だけ外部情報提供者を利用します。固定コレクションへ出力する場合はカタログでケースを解決し、コレクションマニフェスト、所属情報、ファミリー情報源を検証して正規の相対リンクを生成します。",
    "- 日本語化はURL、hash、Markdown link destination、機械可読enum、code fenceを保護し、未解決の英語説明が1行でも残る場合は一括writeを拒否するtransactionalな処理としました。":
        "- 日本語化は URL、ハッシュ、Markdown のリンク先、機械可読の列挙値、コードフェンスを保護し、未解決の英語説明が1行でも残る場合は一括書き込みを拒否するトランザクション処理としました。",
    "- KoiVM 10件はhandler map、VM data map、token call graph、proxy collapse、state reconstructionが未実装です。":
        "- KoiVM 10件は、ハンドラーマップ、仮想機械データマップ、トークン呼び出しグラフ、プロキシの折り畳み、状態復元が未実装です。",
    "- native protector／wrapperはStealC Themida・WinLicense・Enigma・overlay、Valley系protector、Latrodectus AES-CTR、Amadey未知packerなどが残っています。":
        "- ネイティブのプロテクターまたはラッパーでは、StealC の Themida・WinLicense・Enigma・オーバーレイ、Valley 系プロテクター、Latrodectus の AES-CTR、Amadey の未知パッカーなどが残っています。",
    "- managed sampleはToolBelt／njRAT、Snake／Venomでstate variableとresource-to-method dataflowが不足しています。":
        "- マネージド検体では、ToolBelt と njRAT、Snake と Venom で状態変数およびリソースからメソッドへのデータフロー解析が不足しています。",
    "- Agent Teslaの外部stage、Vidarの外部payload 2件、ValleyRATの最終stage 1件は公開byte列がなく、追加取得を許可していないため解析対象にしていません。":
        "- Agent Tesla の外部段階、Vidar の外部ペイロード2件、ValleyRAT の最終段階1件は公開バイト列がなく、追加取得を許可していないため解析対象にしていません。",
    "- 通信先・APIのallowlist、credential境界、path／junction containment、quota、署名付きplugin trustなどのframework hardeningは、詳細報告の未実装項目として列挙しています。":
        "- 通信先と API の許可一覧、認証情報の境界、パスとジャンクションの封じ込め、割当量、署名付きプラグインの信頼管理などのフレームワーク堅牢化は、詳細報告の未実装項目として列挙しています。",
    "監査後のcaseは554件でSHA-256重複0です。マルウェアcaseは452件、未分類は101件、サプライチェーンpayloadは1件です。版は静的根拠で58件、exact sampleの外部報告で4件を特定し、根拠のない491件は `unknown` のまま維持しています。":
        "監査後のケースは554件で、SHA-256の重複は0件です。マルウェアケースは452件、未分類は101件、サプライチェーンのペイロードは1件です。版は静的根拠で58件、完全一致検体に関する外部報告で4件を特定し、根拠のない491件は `unknown` のまま維持しています。",
}

_TERMINAL_PE_ROW = re.compile(
    r"^(?P<prefix>\|\s*\x60[0-9a-f]{64}\x60\s*\|.+\|\s*"
    r"\x60[0-9a-f]{64}\x60\s*\|\s*[0-9,]+\s*\|\s*)"
    r"(?P<architecture>x64 \.NET|x86 native)\s*/\s*not packed"
    r"(?P<suffix>\s*\|)$"
)


def translate_line(line: str) -> str:
    """既知の研究監査行だけを変換し、未知行は変更しない。"""
    leading = line[: len(line) - len(line.lstrip())]
    trailing = line[len(line.rstrip()):]
    core = line.strip()
    exact = _EXACT_TRANSLATIONS.get(core)
    if exact is not None:
        return leading + exact + trailing
    match = _TERMINAL_PE_ROW.fullmatch(core)
    if match:
        architecture = (
            "x64 .NET" if match.group("architecture") == "x64 .NET"
            else "x86 ネイティブ"
        )
        return (
            leading
            + match.group("prefix")
            + architecture
            + "／パッキングなし"
            + match.group("suffix")
            + trailing
        )
    return line
