"""追加9ファミリの解析結果に残る説明文を日本語化する。

共通ローカライザーから独立した後段変換として使う。インラインコード、URL、
Markdownリンク先、ハッシュ、列挙値、ファイル名、識別子は変更しない。
"""

from __future__ import annotations

import re


_EXACT = {
    "- Certificate validity: 2026-07-04 15:16:54Z to 2027-07-05 15:16:54Z":
        "- 証明書の有効期間: 2026-07-04 15:16:54Z から 2027-07-05 15:16:54Z",
    "The sample hash and Casper algorithm/layout remain useful. Do not block `10.0.123.1` globally based on this report.":
        "検体のハッシュとCasperのアルゴリズム／配置は引き続き有用です。この報告だけに基づいて`10.0.123.1`を全体で遮断しないでください。",
    "# Amadey：OSINT詳細": "# Amadey：公開情報の詳細",
    "# ShadowPad：OSINT詳細": "# ShadowPad：公開情報の詳細",
    "# SpyGlace：OSINT詳細": "# SpyGlace：公開情報の詳細",
    "# RemusStealer：OSINT詳細": "# RemusStealer：公開情報の詳細",
    "# AMOSStealer：OSINT詳細": "# AMOSStealer：公開情報の詳細",
    "# LummaStealer：OSINT詳細": "# LummaStealer：公開情報の詳細",
    "# FormBook：OSINT詳細": "# FormBook：公開情報の詳細",
    "# DonutLoader：OSINT詳細": "# DonutLoader：公開情報の詳細",
    "# PureHVNC：OSINT詳細": "# PureHVNC：公開情報の詳細",
    "- **High false-positive risk:** generic access to browser databases, wallets, `osascript`, Go runtime strings, or high-entropy PE sections. Backup, migration, enterprise inventory, installers, and legitimate Go applications can match.":
        "- **高い誤検知リスク:** ブラウザーデータベースやウォレットへの一般的なアクセス、`osascript`、Goランタイム文字列、高エントロピーのPEセクション。バックアップ、移行、企業資産管理、インストーラー、正規のGoアプリケーションでも一致し得ます。",
    "- **Medium false-positive risk:** script interpreter plus network download plus execution, or an unsigned process reading multiple browser/wallet stores. Administrative automation and software deployment can overlap.":
        "- **中程度の誤検知リスク:** スクリプトインタープリター、ネットワークダウンロード、実行の組み合わせ、または複数のブラウザー／ウォレット保管領域を読み取る未署名プロセス。管理用自動化やソフトウェア配備とも重複し得ます。",
    "- Envelope: repeating XOR with sgznqhtgnghvmzxponum":
        "- エンベロープ: sgznqhtgnghvmzxponumを用いた反復XOR",
    "- Mutex: K31610KIO9834PG79A471":
        "- ミューテックス: K31610KIO9834PG79A471",
    "The build-level differentiator from the other EVE samples is the payload hash and mutex suffix. Static command and WinHTTP API sets otherwise match. See config.json for machine-readable details. No C2 request was sent.":
        "他のEVE検体とのビルド単位の差分は、ペイロードのハッシュとミューテックスの接尾辞です。それ以外の静的コマンドとWinHTTP APIの組み合わせは一致します。機械可読な詳細は config.json を参照してください。C2要求は送信していません。",
    "## Reviewed batches": "## 精査済みバッチ",
    "- [VX-Underground batch, 2026-07-16](../../collections/vx-underground-20260716/sources/amadey/README.md):":
        "- [VX-Underground バッチ（2026-07-16）](../../collections/vx-underground-20260716/sources/amadey/README.md):",
    "# Atomic macOS Stealer behavior and C2 assessment":
        "# Atomic macOS Stealerの挙動とC2評価",
    "## Probable exfiltration/C2 configuration":
        "## 情報持ち出し／C2の可能性が高い設定",
    "- 10 submissions: 7 Mach-O files and 3 script stages (VBA, VBS, and AppleScript).":
        "- 投稿物10件: Mach-Oファイル7件とスクリプト段階3件（VBA、VBS、AppleScript）。",
    "- Three script stages exposed keychain, browser, wallet, user-prompt, and AppleScript collection features.":
        "- 三つのスクリプト段階から、キーチェーン、ブラウザー、ウォレット、利用者プロンプト、AppleScriptによる収集機能が確認されました。",
    "The script cases collect or reference macOS keychain material, browser stores, and cryptocurrency-wallet data, and use user prompts/AppleScript as part of the acquisition flow. Script delivery is kept separate from direct Mach-O delivery.":
        "スクリプトのケースは、macOSのキーチェーン情報、ブラウザーの保管データ、暗号資産ウォレットのデータを収集または参照し、取得フローの一部として利用者プロンプトとAppleScriptを使用します。スクリプト経由の配布は、Mach-Oを直接配布するケースと分けて扱います。",
    "Embedded `/ledger/` and `/ledger/live/` pairs were recovered from three scripts:":
        "埋め込まれた`/ledger/`と`/ledger/live/`の組を三つのスクリプトから復元しました:",
    "These are `probable` embedded exfil/C2 values. No DNS, HTTP, or check-in was performed, so server liveness and ownership remain unknown.":
        "これらは埋め込みの情報持ち出し／C2値で、判定は`probable`です。DNS、HTTP、チェックインはいずれも実施していないため、サーバーの稼働状況と所有者は不明です。",
    "- High FP: `osascript`, `security`, `curl`, or browser database access individually.":
        "- 高い誤検知リスク: `osascript`、`security`、`curl`、またはブラウザーデータベースへのアクセスを単独で用いる場合。",
    "- Medium FP: AppleScript credential prompt combined with keychain/browser collection and archive creation.":
        "- 中程度の誤検知リスク: AppleScriptの認証情報プロンプトに、キーチェーン／ブラウザー収集とアーカイブ作成を組み合わせる場合。",
    "- Lower FP: the collection chain plus `/ledger/<64-hex>` infrastructure and an unusual parent/child sequence.":
        "- 低い誤検知リスク: 収集チェーン、`/ledger/<64-hex>`基盤、通常と異なる親子プロセス列の組み合わせ。",
    "same universal Mach-O payload. One arrived as seven concatenated XZ streams":
        "同じユニバーサルMach-Oペイロードです。一つは七本のXZストリームを連結した形で到着し、",
    "containing an Apple disk image; both x86-64 and arm64 slices were recovered.":
        "Appleディスクイメージを含んでいました。x86-64とarm64の両スライスを復元しました。",
    "- Five PE files contained Go runtime evidence; two met the packing heuristic.":
        "- 五つのPEファイルでGoランタイムの痕跡を確認し、そのうち二つがパッキング判定基準を満たしました。",
    "The reviewed set contains distinct encrypted-archive, Go-loader, and native-PE delivery shapes. This separation is retained because they may represent different campaigns or builders. Browser/wallet behavior was not sufficiently exposed in the submitted layer to claim recovered final configuration.":
        "精査対象には、暗号化アーカイブ、Goローダー、ネイティブPEという異なる配布形態が含まれます。別々のキャンペーンまたはビルダーを表す可能性があるため、この区分を維持します。提出レイヤーではブラウザー／ウォレットに関する挙動が十分に現れておらず、最終設定を復元したとは判断できません。",
    "No C2 was confirmed. Three bare `host:port` strings occurred among a larger synthetic/random domain corpus and were suppressed as high-false-positive data rather than published as C2.":
        "C2は確認されませんでした。三つの単純な`host:port`文字列が、より大きな合成／ランダムドメイン集合の中に出現しましたが、C2として公開せず、誤検知リスクの高いデータとして除外しました。",
    "# Lumma Stealer behavior and C2 assessment":
        "# Lumma Stealerの挙動とC2評価",
    "- All ten contained Go loader/runtime evidence; nine met the packing heuristic.":
        "- 全十件でGoローダー／ランタイムの痕跡を確認し、九件がパッキング判定基準を満たしました。",
    "- UPX did not successfully recover any case, so none is labeled UPX-unpacked.":
        "- UPXではいずれのケースも正常に復元できなかったため、UPX展開済みとは分類しません。",
    "The reviewed bytes are consistent with protected or Go-based loader stages rather than plaintext Lumma configuration. Expected browser, wallet, build-ID, HWID, and API fields were not sufficiently correlated in the submitted layer to promote a config.":
        "精査したバイト列は、平文のLumma設定ではなく、保護済みまたはGoベースのローダー段階と整合します。想定されるブラウザー、ウォレット、ビルドID、HWID、APIの各項目は、提出レイヤー内で設定として確定できるほど相関していませんでした。",
    "No C2 literal survived known-benign filtering and family-context validation. The result is `unresolved`, not “no C2.” A final payload or process-attributed sandbox trace is needed for a stronger conclusion.":
        "既知の無害値の除外とファミリー文脈の検証を通過したC2リテラルはありませんでした。結果は「C2なし」ではなく`unresolved`です。より強い結論には、最終ペイロードまたはプロセスに帰属できるサンドボックス追跡結果が必要です。",
    "- 10 recent MalwareBazaar submissions: 6 scripts, 3 XLSM containers, and 1 .NET PE.":
        "- 最近のMalwareBazaar投稿物10件: スクリプト6件、XLSMコンテナー3件、.NET PE 1件。",
    "- The direct PE was high entropy and remained protected. FLOSS reported that .NET deobfuscation was unsupported for that case.":
        "- 直接提出されたPEは高エントロピーで、保護されたままでした。FLOSSは、このケースの.NET難読化解除には対応していないと報告しました。",
    "This is classified as candidate delivery/infrastructure, not confirmed C2. No active request was made. Certificate, Microsoft, and other vendor-reference URLs were filtered.":
        "これは確認済みC2ではなく、配布／基盤の候補として分類します。能動的な要求は送信していません。証明書、Microsoft、その他ベンダー参照用のURLは除外しました。",
    "Eight VX-Underground ShadowPad artifacts were reviewed using static PE inspection, loader decryption, proprietary-module parsing, QuickLZ decompression, and Config-module string recovery. No sample was executed and no recovered endpoint was contacted.":
        "VX-Underground のShadowPad成果物八件を、PEの静的検査、ローダーの復号、独自モジュールの解析、QuickLZ展開、Configモジュールの文字列復元により精査しました。検体は実行せず、復元した接続先にも接続していません。",
    "`confirmed static config` means the value was recovered from the sample's decoded configuration. It does not establish that an endpoint is online, malicious today, or controlled by the same operator. `10.0.123.1` is RFC1918 space and is retained only as builder/test context, not a public C2 IOC.":
        "`confirmed static config`は、検体の復号済み設定から値を復元したことを意味します。接続先が現在オンライン、悪性、または同じ運用者の管理下にあることを示すものではありません。`10.0.123.1`はRFC1918のアドレス空間に属するため、公開C2 IOCではなく、ビルダー／テストの文脈としてのみ保持します。",
    "The reviewed Casper generation decrypts a Root module from a high-entropy PE section, reconstructs proprietary module sections, loads embedded Plugins/Config/Install/transport modules, and keeps its network and persistence strings encrypted. The older x86 configuration is 0x858 bytes; the reviewed x64 generation adds four bytes and uses a 0x85c-byte layout. Both carry installation paths, service masquerades, a Run-key path, injection targets, up to nine server strings, four proxy strings, DNS resolver fields, and retry timing.":
        "精査したCasper世代は、高エントロピーのPEセクションからRootモジュールを復号し、独自モジュールの各セクションを再構築して、埋め込みのPlugins／Config／Install／transportモジュールを読み込む一方、ネットワークと永続化の文字列は暗号化したまま保持します。旧x86設定は0x858バイトで、精査したx64世代は四バイトを追加した0x85cバイトのレイアウトを使用します。いずれもインストールパス、サービス偽装、Runキーのパス、インジェクション対象、最大九個のサーバー文字列、四個のプロキシ文字列、DNSリゾルバー項目、再試行タイミングを格納します。",
    "The newer ScatterBee chain stores a legitimate OLEVIEW executable, `IVIEWERS.dll`, and an opaque encrypted payload in PE resources. The decoded payload configures `Windows_Search_Update`, `wsuhost.exe`, DLL sideloading through `IVIEWERS.dll`, Run-key persistence, `svchost.exe` injection targets, and `TCP://fljhcqwe.com:80`.":
        "新しいScatterBeeチェーンは、正規のOLEVIEW実行ファイル、`IVIEWERS.dll`、内容不明の暗号化ペイロードをPEリソースに格納します。復号したペイロードには、`Windows_Search_Update`、`wsuhost.exe`、`IVIEWERS.dll`を介したDLLサイドローディング、Runキーによる永続化、`svchost.exe`へのインジェクション対象、`TCP://fljhcqwe.com:80`が設定されています。",
    "ShadowPad is modular. Root initializes additional modules and delegates configuration, installation, online state, and transport operations. Public technical reports describe TCP/HTTP/UDP/DNS transports, persistence through services and Run keys, and process injection. Those family capabilities are not automatically attributed as observed execution in these cases; the case reports distinguish decoded intent from host telemetry.":
        "ShadowPadはモジュール型です。Rootは追加モジュールを初期化し、設定、インストール、オンライン状態、通信処理を各モジュールへ委譲します。公開技術報告では、TCP／HTTP／UDP／DNS通信、サービスとRunキーによる永続化、プロセスインジェクションが説明されています。これらのファミリー機能を本ケースで観測した実行として自動的に帰属させず、各ケース報告では復号した意図とホストのテレメトリーを区別します。",
    "| High / Low | Exact reviewed hashes; complete Casper key-schedule cluster plus proprietary-module layout; OLEVIEW loading `IVIEWERS.dll` from an unusual writable directory | Repacked samples evade hashes; internal reverse-engineering fixtures may reproduce the constants |":
        "| 高 / 低 | 精査済みの完全一致ハッシュ、Casperの完全な鍵スケジュール群と独自モジュールレイアウト、通常と異なる書き込み可能ディレクトリから`IVIEWERS.dll`を読み込むOLEVIEW | 再パックされた検体はハッシュ検知を回避します。内部のリバースエンジニアリング用フィクスチャが定数を再現する場合があります |",
    "| Medium / Medium | `TosBtKbd.dll` or `mscoree.dll` sideload pattern combined with high-entropy `.rdata`, service/Run-key creation, and injection into configured system processes | Legitimate Toshiba/.NET components and enterprise service software can share individual names or behaviors |":
        "| 中 / 中 | `TosBtKbd.dll`または`mscoree.dll`のサイドロードパターンと、高エントロピーの`.rdata`、サービス／Runキーの作成、設定済みシステムプロセスへのインジェクションの組み合わせ | 正規のToshiba／.NETコンポーネントや企業向けサービスソフトウェアが個別の名前または挙動を共有する場合があります |",
    "| Low / High | Domain-only or path-only matching; generic Run-key, service creation, or `svchost.exe` injection alerts | Domains can be sinkholed/reassigned; service and Run-key operations are common administration activity |":
        "| 低 / 高 | ドメイン単独またはパス単独の一致、一般的なRunキー／サービス作成、`svchost.exe`インジェクションのアラート | ドメインはシンクホール化または再割当され得ます。サービスとRunキーの操作は一般的な管理作業でもあります |",
    "Use the included YARA rules as triage, then confirm the decoded configuration. Use the Sigma rule only with image-load and path context. Domain indicators should remain supplemental and time-scoped.":
        "同梱のYARAルールをトリアージに使用し、その後で復号済み設定を確認します。Sigmaルールは、イメージ読み込みとパスの文脈がそろう場合にのみ使用します。ドメイン指標は補助的かつ期間を限定した情報として扱います。",
    "## Primary references": "## 主要参考資料",
    "## Role in the chain": "## チェーン内の役割",
    "This hash is the `IVIEWERS.dll` component extracted from the reviewed OLEVIEW resource chain. Its role is DLL sideloading/loading support for the separately encrypted ShadowPad payload. Static PE inspection found 78 imports, a normal `.text` entrypoint, no high-entropy section, and no separate ScatterBee or Casper configuration block.":
        "このハッシュは、精査したOLEVIEWリソースチェーンから抽出した`IVIEWERS.dll`コンポーネントです。役割は、別途暗号化されたShadowPadペイロードのDLLサイドローディング／読み込みを支援することです。PEの静的検査では、インポート78件、通常の`.text`エントリーポイント、高エントロピーセクションなし、独立したScatterBeeまたはCasper設定ブロックなしという結果でした。",
    "The absence of a standalone config is meaningful: `TCP://fljhcqwe.com:80` belongs to the encrypted payload in the parent dropper, not to a value independently recovered from this DLL. The report therefore keeps chain inheritance separate from direct artifact evidence.":
        "独立した設定が存在しないことには意味があります。`TCP://fljhcqwe.com:80`は親ドロッパー内の暗号化ペイロードに属し、このDLLから独立して復元した値ではありません。そのため、本報告ではチェーンから継承した情報と成果物から直接得た根拠を分けて扱います。",
    "No network endpoint was directly recovered from this DLL. Its submitted hash and the parent dropper hash are the publishable relationship indicators. See the parent case for the decoded C2 configuration.":
        "このDLLからネットワーク接続先を直接復元することはできませんでした。提出物のハッシュと親ドロッパーのハッシュが、公開可能な関係指標です。復号済みC2設定は親ケースを参照してください。",
    "Detect OLEVIEW-like processes loading `IVIEWERS.dll` from an unexpected writable directory and correlate with the parent/resource hashes. `IVIEWERS.dll` as a filename alone is insufficient and can produce false positives in copied SDK or inspection-tool environments.":
        "想定外の書き込み可能ディレクトリから`IVIEWERS.dll`を読み込むOLEVIEW系プロセスを検知し、親成果物／リソースのハッシュと相関させます。ファイル名`IVIEWERS.dll`単独では不十分であり、複製されたSDKや検査ツール環境で誤検知が生じ得ます。",
    "The loader seed was found structurally at RVA `0x77f8`; the encrypted stream begins at `0x77fc`. Static decoding recovered the proprietary Root module and a four-state-encrypted, QuickLZ level-1 Config block at decoded offset `0x2d7c`.":
        "ローダーのシードは構造解析によりRVA `0x77f8`で見つかり、暗号化ストリームは`0x77fc`から始まります。静的復号により、独自のRootモジュールと、四状態暗号化されたQuickLZレベル1のConfigブロックを復号後オフセット`0x2d7c`で復元しました。",
    r"Campaign ID is `D0a2MkJLmoTKHbCAn`. Persistence masquerades as `ChromeUpdateService` at `%ALLUSERSPROFILE%\Chrome\AppData\Update\ChromeUpdate.exe`, using `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`. Configured injection targets include both 32-bit and 64-bit Kaspersky NetworkAgent `klrbtagt.exe` paths, `%windir%\system32\svchost.exe`, and `%windir%\system32\taskhost.exe`. These values are static intent rather than observed actions.":
        r"キャンペーンIDは`D0a2MkJLmoTKHbCAn`です。永続化は`ChromeUpdateService`を装い、`%ALLUSERSPROFILE%\Chrome\AppData\Update\ChromeUpdate.exe`で`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`を使用します。設定されたインジェクション対象には、32-bitと64-bitのKaspersky NetworkAgent `klrbtagt.exe`パス、`%windir%\system32\svchost.exe`、`%windir%\system32\taskhost.exe`が含まれます。これらの値は静的に復元した意図であり、観測した動作ではありません。",
    "The config contains `www.grandfoodtony.com` on ports 80, 443, and 8080 for each of TCP, HTTP, and UDP. All nine protocol entries are confirmed static config values. Public campaign reporting also associates this domain with ShadowPad activity, but current liveness was not tested.":
        "設定にはTCP、HTTP、UDPの各方式について、`www.grandfoodtony.com`のポート80、443、8080が含まれます。九つのプロトコル項目はすべて確認済みの静的設定値です。公開キャンペーン報告でもこのドメインはShadowPad活動に関連付けられていますが、現在の稼働状況は検証していません。",
    "The strongest static rule combines the x86 outer key schedule, proprietary module header, Config flags `0x12345678`, QuickLZ framing, and TosBtKbd sideload context. Detecting `ChromeUpdateService` alone has medium-to-high false-positive risk; combining the exact path, Kaspersky injection targets, and network domain lowers it. Domain-only detection remains time-sensitive.":
        "最も強い静的ルールは、x86外層の鍵スケジュール、独自モジュールヘッダー、Configフラグ`0x12345678`、QuickLZフレーミング、TosBtKbdサイドロードの文脈を組み合わせます。`ChromeUpdateService`単独の検知は中から高程度の誤検知リスクがありますが、完全一致パス、Kasperskyのインジェクション対象、ネットワークドメインを組み合わせるとリスクが下がります。ドメイン単独の検知は引き続き時間経過の影響を受けます。",
    "Reference: [Kaspersky ICS ShadowPad campaign analysis](https://ics-cert.kaspersky.com/publications/reports/2022/06/27/attacks-on-industrial-control-systems-using-shadowpad/).":
        "参考資料: [Kaspersky ICSによるShadowPadキャンペーン解析](https://ics-cert.kaspersky.com/publications/reports/2022/06/27/attacks-on-industrial-control-systems-using-shadowpad/)。",
    "The outer seed is at RVA `0xa260`. The x64 key schedule recovered a proprietary Root module, five embedded modules, and a single-byte-XOR/QuickLZ Config block at decoded offset `0x4bf7`. Module ID 102 contains the x64 string schedule; reversing it enabled complete 0x85c-byte config recovery.":
        "外層シードはRVA `0xa260`にあります。x64の鍵スケジュールから、独自のRootモジュール、五つの埋め込みモジュール、単一バイトXOR／QuickLZのConfigブロックを復号後オフセット`0x4bf7`で復元しました。モジュールID 102にはx64の文字列スケジュールが含まれ、これを逆算することで0x85cバイトの設定全体を復元できました。",
    r"Campaign ID is `3vS89RZxQNWSgQTu1`. Installation masquerades as `Remote RT` / `Remote Registry Tools` at `%SystemRoot%\System32\ras\remote.exe`, with `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and value `Remote Registry`. Three injection-target slots are empty; the fallback is `%windir%\system32\svchost.exe`.":
        r"キャンペーンIDは`3vS89RZxQNWSgQTu1`です。インストールは`Remote RT`／`Remote Registry Tools`を装い、`%SystemRoot%\System32\ras\remote.exe`で`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`と値`Remote Registry`を使用します。三つのインジェクション対象スロットは空で、フォールバックは`%windir%\system32\svchost.exe`です。",
    "The only server string is `https://goods.kankuedu.org`. It is a confirmed static config URL. No explicit port is encoded, so HTTPS convention implies 443 only as an inference; the IOC record does not add an unobserved port.":
        "唯一のサーバー文字列は`https://goods.kankuedu.org`. 確認済みの静的設定URLです。明示的なポートは符号化されていないため、HTTPSの慣例から443を推定できるに過ぎず、IOCレコードには未観測のポートを追加しません。",
    "High-confidence static detection uses the x64 outer key schedule, Config flags, 0x85c layout, module ID 102, and x64 string-key constants. `remote.exe`, Remote Registry wording, and Run-key activity alone are high-noise administrator/service patterns. Correlate them with the exact path and config URL.":
        "高確度の静的検知では、x64外層の鍵スケジュール、Configフラグ、0x85cレイアウト、モジュールID 102、x64文字列鍵の定数を使用します。`remote.exe`、Remote Registryという文言、Runキーの動作はいずれも単独ではノイズの多い管理者／サービスのパターンです。完全一致パスと設定URLを相関させてください。",
    r"Persistence masquerades as `VMware Snapshot Provider Service` and installs `%ProgramData%\VMware\RawdskCompatibility\virtual\vmrawdsk.exe` through the Windows Run key. The four configured injection targets are `%windir%\system32\svchost.exe`, `%windir%\system32\winlogon.exe`, `%windir%\system32\taskhost.exe`, and another `svchost.exe` fallback.":
        r"永続化は`VMware Snapshot Provider Service`を装い、Windows Runキーを介して`%ProgramData%\VMware\RawdskCompatibility\virtual\vmrawdsk.exe`をインストールします。設定された四つのインジェクション対象は、`%windir%\system32\svchost.exe`、`%windir%\system32\winlogon.exe`、`%windir%\system32\taskhost.exe`、および別の`svchost.exe`フォールバックです。",
    "The config contains TCP and HTTP entries for `websencl.com` on ports 8080, 80, and 443. UDP slots are empty. Confidence is `confirmed_static_config`; no liveness or ownership test was performed.":
        "設定には`websencl.com`のポート8080、80、443に対するTCPとHTTPの項目が含まれます。UDPスロットは空です。確度は`confirmed_static_config`で、稼働状況や所有者の検証は実施していません。",
    r"Correlate the Casper key schedule and module layout with the VMware-masquerading path and `websencl.com`. VMware service names and paths in isolation can collide with legitimate virtualization software, giving a medium false-positive risk. The exact nonstandard `RawdskCompatibility\virtual\vmrawdsk.exe` path plus decoded domain is substantially stronger.":
        r"Casperの鍵スケジュールとモジュールレイアウトを、VMware偽装パスおよび`websencl.com`と相関させます。VMwareのサービス名やパスは、単独では正規の仮想化ソフトウェアと重複し得るため、誤検知リスクは中程度です。標準外の完全一致パス`RawdskCompatibility\virtual\vmrawdsk.exe`と復号済みドメインの組み合わせは大幅に強い根拠となります。",
    r"Combine the x64 Casper algorithm/layout rule with the unusual `C:\Windows\inf\Termservice\tslabels.exe` path and the configured domain. `System Event Manager` alone is generic and creates substantial false positives. Dynamic analytics should correlate service or Run-key persistence, the unusual binary path, and subsequent HTTPS activity.":
        r"x64 Casperのアルゴリズム／レイアウトルールを、通常と異なる`C:\Windows\inf\Termservice\tslabels.exe`パスおよび設定済みドメインと組み合わせます。`System Event Manager`単独では一般的すぎて、多数の誤検知が生じます。動的解析では、サービスまたはRunキーによる永続化、通常と異なるバイナリパス、その後のHTTPS通信を相関させる必要があります。",
    "The entrypoint is in the 7.996-entropy `.nsp1` section; `.nsp0` has 143,360 virtual bytes and no raw bytes. Only six imports are exposed. The generic Casper stream detector cannot reach the inner loader without an nsPack restoration stage, so `config.json` intentionally reports no local config rather than guessing.":
        "エントリーポイントはエントロピー7.996の`.nsp1`セクションにあり、`.nsp0`は仮想サイズ143,360バイトで、生のバイト列を持ちません。公開されるインポートは六件だけです。汎用Casperストリーム検出器はnsPackの復元段階なしでは内部ローダーに到達できないため、`config.json`は推測せず、ローカル設定なしと意図的に報告します。",
    "The submitted SHA-256 exactly matches Dr.Web's `BackDoor.ShadowPad.1` technical entry. That primary source documents the same TosBtKbd/Casper module format, four-state plugin/config decryption, QuickLZ compression, 0x858-byte config structure, and config strings for this sample. This report labels those values `confirmed_public_exact_hash`, distinct from the `confirmed_static_config` label used when this repository independently decrypts bytes.":
        "提出物のSHA-256 は Dr.Web の技術項目`BackDoor.ShadowPad.1`と完全一致します。その一次情報には、同じTosBtKbd／Casperモジュール形式、四状態のプラグイン／設定復号、QuickLZ圧縮、0x858バイトの設定構造、この検体の設定文字列が記載されています。本報告では、それらの値を`confirmed_public_exact_hash`と分類し、本リポジトリがバイト列を独自に復号した場合の`confirmed_static_config`とは区別します。",
    "Dr.Web records `www.pneword.net` across HTTP, TCP, and UDP with ports 80, 443, and 53. Resolver `8.8.8.8` is common infrastructure and is excluded from the IOC list. No current liveness test was performed.":
        "Dr.Web は`www.pneword.net`を、HTTP、TCP、UDPのポート80、443、53として記録しています。リゾルバー`8.8.8.8`は一般的な基盤であるためIOC一覧から除外します。現在の稼働状況は検証していません。",
    "Use the exact hash for high-confidence historical detection. A structural rule may combine the `.nsp0/.nsp1/.nsp2` shape, TosBtKbd sideload context, and restored Casper key schedule. nsPack section names or entropy alone are broad packer indicators and have high false-positive risk across unrelated malware and protected software.":
        "過去検体の高確度検知には完全一致ハッシュを使用します。構造ルールでは、`.nsp0/.nsp1/.nsp2`の形状、TosBtKbdサイドロードの文脈、復元したCasper鍵スケジュールを組み合わせられます。nsPackのセクション名やエントロピー単独は広範なパッカー指標であり、無関係なマルウェアや保護ソフトウェアで高い誤検知リスクがあります。",
    r"The seed at RVA `0x7808` decrypts the same x86 Casper Root and 0x858-byte Config format as the other TosBtKbd cases. Campaign ID is `CLwKvjhHyeuLPsS6Z`. It installs `%ALLUSERSPROFILE%\MUI\service.exe`, uses service/Run-key name `MUI`, and configures injection into `svchost.exe`, `taskhost.exe`, `SearchIndexer.exe`, and `winlogon.exe`.":
        r"RVA `0x7808`のシードは、他のTosBtKbdケースと同じx86 Casper Rootと0x858バイトのConfig形式を復号します。キャンペーンIDは`CLwKvjhHyeuLPsS6Z`です。`%ALLUSERSPROFILE%\MUI\service.exe`をインストールし、サービス／Runキー名`MUI`を使用して、`svchost.exe`、`taskhost.exe`、`SearchIndexer.exe`、`winlogon.exe`へのインジェクションを設定します。",
    "The server slots contain HTTP and TCP variants of `10.0.123.1` on ports 65234, 8080, and 57223. Because `10.0.123.1` is RFC1918 private space, these are confirmed builder/test configuration values but are `context_only`, not publishable Internet C2 IOCs. They may indicate an internal test environment, an unfinished build, or a configuration template.":
        "サーバースロットには、`10.0.123.1`のポート65234、8080、57223に対するHTTPとTCPの亜種が含まれます。`10.0.123.1`はRFC1918のプライベートアドレス空間に属するため、これらは確認済みのビルダー／テスト設定値ではありますが、公開可能なインターネットC2 IOCではなく`context_only`とします。内部テスト環境、未完成のビルド、設定テンプレートを示す可能性があります。",
    "The sample hash and Casper algorithm/layout remain useful. Do not block `10.0.123.1` globally based on this report: private address reuse makes that condition extremely prone to false positives. Host analytics should instead focus on the exact MUI installation path combined with persistence and the loader signature.":
        "検体ハッシュとCasperのアルゴリズム／レイアウトは引き続き有用です。本報告だけを根拠に`10.0.123.1`を全体で遮断してはなりません。プライベートアドレスは再利用されるため、この条件は極めて誤検知しやすくなります。ホスト解析では、完全一致するMUIインストールパスと永続化およびローダーシグネチャの組み合わせに注目します。",
    r"The decoded configuration uses `Windows_Search_Update`, `wsuhost.exe`, and `IVIEWERS.dll`. Candidate installation locations include `%ProgramFiles%\Windows_Search_Update\wsuhost.exe` and `%ALLUSERSPROFILE%\DRM\Windows_Search_Update\wsuhost.exe`. It contains the Windows Run-key path and `svchost.exe` injection targets. These are decoded intended behaviors, not observed host events.":
        r"復号済み設定では`Windows_Search_Update`、`wsuhost.exe`、`IVIEWERS.dll`を使用します。インストール先候補には`%ProgramFiles%\Windows_Search_Update\wsuhost.exe`と`%ALLUSERSPROFILE%\DRM\Windows_Search_Update\wsuhost.exe`が含まれます。Windows Runキーのパスと`svchost.exe`のインジェクション対象も格納します。これらは復号した意図上の挙動であり、観測したホストイベントではありません。",
    "High-confidence correlation combines the submitted hash, the encrypted resource hash, the embedded `IVIEWERS.dll` hash, and OLEVIEW loading `IVIEWERS.dll` from a user-writable or unexpected directory. String-only matching on `OLEVIEW` has high false-positive risk because OLE/COM inspection tooling is legitimate. Domain-only detection is medium-to-high risk over time due to expiration, reassignment, or sinkholing.":
        "高確度の相関では、提出物のハッシュ、暗号化リソースのハッシュ、埋め込み`IVIEWERS.dll`のハッシュ、利用者が書き込み可能または想定外のディレクトリからOLEVIEWが`IVIEWERS.dll`を読み込む動作を組み合わせます。OLE／COM検査ツールは正規に利用されるため、`OLEVIEW`の文字列単独一致は誤検知リスクが高くなります。ドメイン単独の検知は、有効期限切れ、再割当、シンクホール化により、時間の経過とともに中から高程度のリスクになります。",
    "Primary chain comparison: [Cyfirma ShadowPad malware report](https://www.cyfirma.com/research/shadowpad-malware-report/). Decryption implementation comparison: [PwC ScatterBee scripts](https://github.com/PwCUK-CTO/ScatterBee_Analysis).":
        "主要チェーンの比較: [CyfirmaのShadowPadマルウェア報告](https://www.cyfirma.com/research/shadowpad-malware-report/)。復号実装の比較: [PwCのScatterBeeスクリプト](https://github.com/PwCUK-CTO/ScatterBee_Analysis)。",
    "# SpyGlace / APT-C-60": "# SpyGlace / APT-C-60 解析結果",
    "This directory separates publish-safe SpyGlace results from reusable analysis code. No raw or decoded malware is stored here.":
        "このディレクトリでは、公開可能なSpyGlaceの結果と再利用可能な解析コードを分離しています。未加工または復号済みのマルウェアは保存していません。",
    "All four v3.1.15 repository artifacts were decoded with the repeating repository key and parsed without execution. Three share the EVE campaign configuration at 31.58.136.207; one uses SAPPHIRE at 185.18.222.241. The six later-version hashes were unavailable in surviving public history and MalwareBazaar at the observation date.":
        "リポジトリ内のv3.1.15成果物四件を反復リポジトリ鍵で復号し、実行せずに解析しました。三件は31.58.136.207のEVEキャンペーン設定を共有し、一件は185.18.222.241のSAPPHIREを使用します。後期版のハッシュ六件は、観測日時点で残存する公開履歴とMalwareBazaarのいずれからも取得できませんでした。",
    "# SpyGlace v3.1.15 - 9394627e...":
        "# SpyGlace v3.1.15 - 9394627e... の解析結果",
    "# SpyGlace v3.1.15 - add013bf...":
        "# SpyGlace v3.1.15 - add013bf... の解析結果",
    "# SpyGlace v3.1.15 - c86f319f...":
        "# SpyGlace v3.1.15 - c86f319f... の解析結果",
    "# SpyGlace v3.1.15 - e5f2c706...":
        "# SpyGlace v3.1.15 - e5f2c706... の解析結果",
    "- Mutex: K31610KIO9834PG79797":
        "- ミューテックス: K31610KIO9834PG79797",
    "- Mutex: K31610KIO9834PG79787":
        "- ミューテックス: K31610KIO9834PG79787",
    "The sample shares its C2, user ID and path set with two other recovered EVE builds, but not their exact mutex suffix or PE hash. See config.json for the normalized command/API list. No C2 request was sent.":
        "この検体は、C2、利用者ID、パスの組を、復元済みの別のEVEビルド二件と共有しますが、ミューテックスの完全一致接尾辞とPEハッシュは共有しません。正規化済みのコマンド／API一覧は config.json を参照してください。C2要求は送信していません。",
    "The inferred URLs are the C2 IP combined with each decoded ASP path. They were not contacted. The sample exposes process execution, download/upload, disk enumeration, screenshot and extension-control commands. See config.json for the normalized command/API list, persistence strings, provenance and limitations.":
        "推定URLはC2 IPと復号済みの各ASPパスを組み合わせたもので、接続は行っていません。検体からは、プロセス実行、ダウンロード／アップロード、ディスク列挙、画面取得、拡張子制御の各コマンドが確認できます。正規化済みのコマンド／API一覧、永続化文字列、由来、制約は config.json を参照してください。",
    "High-confidence file detection uses several encoded API, command and config markers together. A single IP or provider access is lower confidence because infrastructure can change and the providers are legitimate. No payload was executed and no credential was collected.":
        "高確度のファイル検知では、符号化された複数のAPI、コマンド、設定マーカーを組み合わせます。基盤は変更され得て、プロバイダー自体は正規であるため、単一IPまたはプロバイダーへのアクセスだけでは確度が低くなります。ペイロードは実行せず、認証情報も収集していません。",
    "- High FP: archive extraction, Go runtime markers, or random domain test data.":
        "- 高い誤検知リスク: アーカイブ展開、Goランタイムマーカー、またはランダムなドメイン試験データ。",
    "- Medium FP: archive-launched unsigned executable followed by browser database access.":
        "- 中程度の誤検知リスク: アーカイブから起動した未署名実行ファイルに続く、ブラウザーデータベースへのアクセス。",
    "- Lower FP: Remus-specific payload strings plus browser/wallet collection and process-attributed exfiltration.":
        "- 低い誤検知リスク: Remus固有のペイロード文字列に、ブラウザー／ウォレット収集とプロセスに帰属できる情報持ち出しを組み合わせる場合。",
    "## 2026-07-15 unpacking reassessment":
        "## 2026-07-15 アンパック再評価",
    "- x64 PE, zero imports, .rdata entropy 7.9942, API hash resolution, approximately 0x36400-byte RWX allocation, and an in-memory loader were confirmed.":
        "- x64 PE、インポートなし、.rdataのエントロピー7.9942、APIハッシュ解決、約0x36400バイトのRWX割当、メモリ内ローダーを確認しました。",
    "- Ghidra analysis identified the bespoke transform/state-machine area around 0x140001730; no stable constant-key transform could be extracted safely.":
        "- Ghidra解析により、0x140001730付近の独自変換／状態機械領域を特定しましたが、安定した定数鍵変換を安全に抽出することはできませんでした。",
    "- Blocker: native_control_flow_obfuscation. The sample and loader stub were not executed or emulated.":
        "- 未解決要因: native_control_flow_obfuscation。検体とローダースタブは実行もエミュレーションもしていません。",
    "- High FP: Go runtime strings, large symbol tables, or high-entropy PE sections.":
        "- 高い誤検知リスク: Goランタイム文字列、大規模なシンボルテーブル、または高エントロピーのPEセクション。",
    "- Medium FP: unsigned Go executable followed by browser/wallet access or staged payload execution.":
        "- 中程度の誤検知リスク: 未署名のGo実行ファイルに続く、ブラウザー／ウォレットへのアクセスまたは段階的なペイロード実行。",
    "- Lower FP: recovered Lumma family/config strings plus credential collection and matching network activity.":
        "- 低い誤検知リスク: 復元したLummaのファミリー／設定文字列に、認証情報収集と対応するネットワーク活動を組み合わせる場合。",
    "# Lumma Stealer": "# Lumma Stealer 解析結果",
    "Formbook/XLoader payloads are expected to collect browser and mail credentials and to use process-injection APIs. In this set, most submissions were delivery stages, so those payload-level behaviors were not uniformly visible. Script and Office indicators must therefore be kept separate from final-payload attribution.":
        "Formbook／XLoaderのペイロードは、ブラウザーとメールの認証情報を収集し、プロセスインジェクションAPIを使用すると想定されます。本集合では提出物の大半が配布段階だったため、これらのペイロード水準の挙動は一様には確認できませんでした。そのため、スクリプトとOfficeの指標は最終ペイロードへの帰属と分けて扱う必要があります。",
    "- High FP: `wscript`/PowerShell usage, XLSM macros, or Cloudflare Workers in isolation.":
        "- 高い誤検知リスク: `wscript`／PowerShellの使用、XLSMマクロ、またはCloudflare Workersを単独で用いる場合。",
    "- Medium FP: a script host downloading a binary and spawning `rundll32`, `regsvr32`, or `mshta`.":
        "- 中程度の誤検知リスク: スクリプトホストがバイナリをダウンロードし、`rundll32`、`regsvr32`、`mshta`のいずれかを起動する場合。",
    "- Lower FP: correlate delivery URL, family payload strings, credential-store access, and process-injection telemetry.":
        "- 低い誤検知リスク: 配布URL、ファミリーペイロード文字列、認証情報保管領域へのアクセス、プロセスインジェクションのテレメトリーを相関できる場合。",
    "| Primary artifact | Static delivery profile | Donut status | Terminal result |":
        "| 主要成果物 | 静的配布プロファイル | Donutの状態 | 終端結果 |",
    "The `e8a4?` submission was reassigned here after the original two Triage inputs":
        "提出物`e8a4?`は、元の二つのTriage入力が",
    "were reported as reversed. Independent reanalysis recovered four PE artifacts":
        "逆転していると報告された後、この場所へ再割り当てされました。独立した再解析で四つのPE成果物を復元しましたが、",
    "but no supported Donut call-over-instance layout. It is retained as a disputed":
        "対応済みのDonut call-over-instanceレイアウトは確認できませんでした。係争中の",
    "direct current-layout Donut shellcode and a 32-byte XOR PE wrapper. Both terminal":
        "現行レイアウトのDonutシェルコードと32バイトXOR PEラッパーとして保持します。どちらの終端",
    "# Reassigned DonutLoader submission: index-XOR multi-PE chain":
        "# 再割当されたDonutLoader提出物: index-XORマルチPEチェーン",
    "- Primary SHA-256: `e8a4f2026d5aac1b74acbf7033ea0ec626055d3dbf5d645c9f741a75ad17ea37`":
        "- 主要SHA-256: `e8a4f2026d5aac1b74acbf7033ea0ec626055d3dbf5d645c9f741a75ad17ea37`",
    "- Requested analysis assignment: DonutLoader":
        "- 要求された解析上の割当: DonutLoader",
    "- Terminal payload: native `10FX` RAT / PureHVNC-like, high confidence":
        "- 終端ペイロード: ネイティブ`10FX` RAT／PureHVNC系、高い確度",
    "reversed. The directory follows the corrected DonutLoader assignment, but the":
        "逆転していました。ディレクトリは修正後のDonutLoader割当に従いますが、",
    "- Confidence: high; adjacent static config strings and terminal protocol markers":
        "- 確度: 高。隣接する静的設定文字列と終端プロトコルマーカー",
    "- Frame header: three little-endian `uint32` values":
        "- フレームヘッダー: 三つのリトルエンディアン`uint32`値",
    "- Magic: `0x58463031` (`10FX` in memory bytes)":
        "- マジック: `0x58463031`（メモリ内バイトでは`10FX`）",
    "- Type roles observed statically: heartbeat/echo, registration JSON, shell,":
        "- 静的に確認した型の役割: ハートビート／エコー、登録JSON、シェル、",
    "binary input, task JSON, plugin and SOCKS5 relay":
        "バイナリ入力、タスクJSON、プラグイン、SOCKS5リレー",
    "The extractor now associates an IP only with an adjacent standalone port or an":
        "抽出器は現在、IPを隣接する単独ポートまたは",
    "The loader uses a renamed Microsoft host and adjacent `netutils.dll`, performs":
        "ローダーは名前を変更したMicrosoftホストと隣接する`netutils.dll`を使用し、",
    "kill-AV and BYOVD logic. The terminal RAT exposes screen capture and streaming,":
        "AV停止とBYOVD処理を行います。終端RATは画面取得とストリーミング、",
    "SOCKS5, plugins, update and restart functions. These are static capabilities;":
        "SOCKS5、プラグイン、更新、再起動の機能を備えます。これらは静的に確認した機能であり、",
    "- Low FP: exact malicious hashes, the recovered terminal hash plus `10FX`":
        "- 低い誤検知リスク: 完全一致の悪性ハッシュ、復元済み終端ハッシュと`10FX`の組み合わせ、",
    "capability cluster, or the full side-load/persistence/C2 correlation.":
        "機能群、または完全なサイドロード／永続化／C2相関。",
    "- Medium FP: renamed `easinvoker.exe` loading adjacent `netutils.dll` followed by":
        "- 中程度の誤検知リスク: 名前を変更した`easinvoker.exe`が隣接する`netutils.dll`を読み込み、その後に",
    "side-load DLLs or configure exclusions.":
        "DLLをサイドロードするか除外設定を行う場合。",
    "- High FP: filename `netutils.dll`, the lure name, port 8080, or a single":
        "- 高い誤検知リスク: ファイル名`netutils.dll`、誘導用の名前、ポート8080、または単一の",
    "# PureHVNC / PureRAT": "# PureHVNC / PureRAT 解析結果",
    "# PureHVNC / PureRAT analysis results":
        "# PureHVNC / PureRAT 解析結果",
    "| `e5541255...d5633d0` | managed PureRAT 4.4.1 | CHRD/WAV ? Donut ? .NET loader | `tirakian.com:56001`, `:56002`, `:56003` | confirmed static config |":
        "| `e5541255...d5633d0` | 管理型PureRAT 4.4.1 | CHRD/WAV ? Donut ? .NETローダー | `tirakian.com:56001`, `:56002`, `:56003` | 確認済み静的設定 |",
    "The full terminal payload and protobuf configuration are recoverable from the":
        "完全な終端ペイロードとprotobuf設定は、",
    "# Managed PureRAT 4.4.1 through CHRD/Donut delivery":
        "# CHRD/Donut配布を介した管理型PureRAT 4.4.1",
    "## Scope and identity": "## 対象範囲と識別情報",
    "- Primary malicious DLL: hidden `AppVIsvSubsystems64.dll`":
        "- 主要な悪性DLL: 隠し`AppVIsvSubsystems64.dll`",
    "- Primary SHA-256: `e55412555b4699c6d3ce2ac60df81eb1ee0d5aa412a303555c8f64037d5633d0`":
        "- 主要SHA-256: `e55412555b4699c6d3ce2ac60df81eb1ee0d5aa412a303555c8f64037d5633d0`",
    "- Terminal family: managed PureRAT / PureHVNC, confirmed":
        "- 終端ファミリー: 管理型PureRAT／PureHVNC、確認済み",
    "- Delivery profile: CHRD/WAV → Donut → .NET resource loader":
        "- 配布プロファイル: CHRD/WAV → Donut → .NETリソースローダー",
    "## Fully recovered chain": "## 完全に復元したチェーン",
    "a 298,635-value Jacobi segment (80 iterations) and a 53,587-value affine segment.":
        "298,635個の値からなるJacobi区間（80回反復）と、53,587個の値からなるアフィン区間。",
    "Donut uses the modern `0x290` layout, Chaskey CTR, entropy profile 3 and an":
        "Donutは最新の`0x290`レイアウト、Chaskey CTR、エントロピープロファイル3、および",
    "uncompressed type-2 .NET EXE module for runtime `v4.0.30319`, AppDomain":
        "非圧縮type-2 .NET EXEモジュール（ランタイム`v4.0.30319`向け）、AppDomain",
    "`PN33Y67X`. The terminal loader applies TripleDES-CBC, PKCS#7 validation and":
        "`PN33Y67X`を使用します。終端ローダーはTripleDES-CBC、PKCS#7検証、および",
    "## Terminal configuration and C2": "## 終端設定とC2",
    "- Persistence: false; prevent-sleep: false; scheduled task and mutex empty":
        "- 永続化: false。スリープ防止: false。スケジュールタスクとミューテックスは空",
    "- PFX SHA-256: `01034a2cf003614de716ee94393e0fb2a80e6f1d0ddead61b4cb57c200f4cb96`":
        "- PFX証明書のSHA-256: `01034a2cf003614de716ee94393e0fb2a80e6f1d0ddead61b4cb57c200f4cb96`",
    "- Leaf DER SHA-256: `67260a713ab105197098882f6d126f89fe4f48df8013f8bba1d2c9307b17410b`":
        "- リーフDER SHA-256: `67260a713ab105197098882f6d126f89fe4f48df8013f8bba1d2c9307b17410b`",
    "The config is a Base64/GZip/protobuf object in the terminal assembly. The agent":
        "設定は終端アセンブリ内のBase64/GZip/protobufオブジェクトです。エージェントは",
    "contains TLS client-authentication, GZip and protobuf serialization logic plus":
        "TLSクライアント認証、GZip、protobufシリアライズ処理に加えて",
    "browser, wallet, Telegram, in-memory module, registry and task capabilities.":
        "ブラウザー、ウォレット、Telegram、メモリ内モジュール、レジストリ、タスクの各機能を備えます。",
    "Flags describe this build and do not prove all capabilities executed.":
        "フラグはこのビルドの内容を示しますが、すべての機能が実行されたことを証明するものではありません。",
    'and `ssl.cert.subject.cn:"PureRAT Agent"`. No live banner was collected, so':
        'および`ssl.cert.subject.cn:"PureRAT Agent"`を含みます。稼働中のバナーは取得していないため、',
    "banner hash, HTTP title, JARM and current service state remain unknown.":
        "バナーハッシュ、HTTPタイトル、JARM、現在のサービス状態は不明です。",
    "- Low FP: exact hashes, decoded C2/campaign/certificate combination, or a":
        "- 低い誤検知リスク: 完全一致ハッシュ、復号済みC2／キャンペーン／証明書の組み合わせ、または",
    "successful CHRD→Donut→PureRAT recovery.":
        "CHRD→Donut→PureRATの復元成功。",
    "- Medium FP: PDF-named Excel host loading adjacent `AppVIsvSubsystems64.dll`,":
        "- 中程度の誤検知リスク: PDFの名前を装ったExcelホストが隣接する`AppVIsvSubsystems64.dll`を読み込む場合、",
    "- High FP: AppV/Excel filenames, GZip/protobuf/TLS strings, a generic PureRAT":
        "- 高い誤検知リスク: AppV／Excelのファイル名、GZip／protobuf／TLS文字列、一般的なPureRAT",
    "YARA covers delivery, resource loader and terminal profiles. Sigma covers the":
        "YARAは配布、リソースローダー、終端の各プロファイルを対象とします。Sigmaは",
    "| none recovered | - | - | static extraction incomplete |":
        "| 復元なし | - | - | 静的抽出未完了 |",
    "- Confirmed C2 status requires the reviewed custom-alphabet/Base64 config structure; literal-only URLs remain candidates.":
        "- 確認済みの指令制御（C2）先と判断するには、精査済みの独自文字表／基数64設定構造が必要です。文字列だけの接続先は候補に留めます。",
    "- Themida/WinLicense wrappers require a recovered inner PE before configuration extraction can be complete.":
        "- Themida／WinLicenseラッパーでは、内部実行形式を復元しない限り設定抽出は完了しません。",
    "- No recovered endpoint was contacted.":
        "- 復元した接続先には接続していません。",
    "- The `/ledger/` URL pattern is treated as probable exfil/C2 infrastructure, not proof of server ownership.":
        "- `/ledger/`の接続先パターンは、情報持ち出し／指令制御（C2）基盤の可能性が高い候補として扱います。サーバー所有者を証明するものではありません。",
    "- Script and macro submissions can be delivery stages rather than the final Mach-O payload.":
        "- スクリプトやマクロの投稿物は、最終Mach-Oペイロードではなく配信段階である可能性があります。",
    "- Formbook payload configuration is commonly encrypted and may require a recovered process image.":
        "- Formbookペイロードの設定は通常暗号化されており、復元したプロセスイメージが必要になる場合があります。",
    "- Loader URLs and certificate references are not promoted to confirmed C2.":
        "- ローダーの接続先と証明書参照だけでは、確認済み指令制御（C2）先へ昇格しません。",
    "- Current Lumma deliveries often contain a loader or protected layer instead of plaintext final config.":
        "- 現在のLumma配信物は、平文の最終設定ではなくローダーまたは保護層を含む場合が多くあります。",
    "- Literal infrastructure remains candidate until family config use is established.":
        "- 文字列として現れる基盤は、ファミリ設定での使用が確認されるまで候補に留めます。",
    "- Encrypted inner 7z deliveries require the campaign password; password guessing is not performed.":
        "- 暗号化された内部7z配信物にはキャンペーンのパスワードが必要です。パスワード推測は行いません。",
    "- Remus attribution and infrastructure require recovered payload-level corroboration.":
        "- Remusへの帰属と基盤の確定には、復元ペイロード水準の裏付けが必要です。",
    "- Analysis: static only; no execution and no endpoint contact":
        "- 解析: 静的解析のみ。実行および接続先への通信は未実施",
    "## Decryption and configuration": "## 復号と設定",
    "## Reviewed set": "## 精査対象",
    "## Behavior model": "## 挙動モデル",
    "## Identity": "## 識別情報",
    "## Static configuration": "## 静的設定",
    "## Infrastructure": "## 基盤",
    "## Coverage": "## 対象範囲",
    "## Results and code": "## 結果とコード",
    "## Infection chain": "## 感染チェーン",
    "## Behavior and configuration": "## 挙動と設定",
    "## Packing and attribution": "## パッキングと帰属",
    "## family固有方針": "## ファミリ固有方針",
    "## unknown（不明）": "## 未識別",
    "## VX-Underground batch, 2026-07-16":
        "## VX-Underground 解析結果（2026-07-16）",
    "- [Dr.Web BackDoor.ShadowPad.1 technical description](https://vms.drweb.com/virus/?i=21995048)":
        "- [Dr.Web BackDoor.ShadowPad.1 技術解説](https://vms.drweb.com/virus/?i=21995048)",
    "- Samples were never executed and recovered layers are not committed.":
        "- 検体は一度も実行しておらず、復元層もリポジトリへ保存していません。",
    "- External infrastructure was not contacted.":
        "- 外部基盤には接続していません。",
    "- Unknown packers and password-protected nested archives remain unresolved.":
        "- 未知のパッカーとパスワード保護された入れ子アーカイブは未解決です。",
    "- MalwareBazaar signature attribution is a lead and was retained separately from static evidence.":
        "- MalwareBazaarのシグネチャ帰属は手掛かりであり、静的根拠とは分けて保持しています。",
    "No active C2 check-in was performed. Use `analysis-framework/common/c2_candidate_detector.py` for offline assessment and passive-query generation.":
        "能動的な指令制御（C2）チェックインは行っていません。オフライン評価と受動問い合わせの生成には`analysis-framework/common/c2_candidate_detector.py`を使用します。",
    "C2 availability was not tested. ASP URLs in case files are inferred combinations of static IPs and paths, not proof that an endpoint answered.":
        "指令制御（C2）先の稼働確認は行っていません。ケースファイル内のASP接続先は静的IPとパスを組み合わせた推定値であり、接続先が応答した証拠ではありません。",
}


_PHRASES = (
    ("MaaS（サービス型マルウェア）", "サービス型マルウェア"),
    ("Palo Alto Networks Unit 42", "パロアルトネットワークスUnit 42"),
    ("Microsoft Digital Crimes Unit", "マイクロソフトデジタル犯罪対策部門"),
    ("Kaspersky Securelist", "カスペルスキー公式ブログ"),
    ("Kaspersky NetworkAgent", "カスペルスキーNetworkAgent"),
    ("Kaspersky ICS", "カスペルスキーICS"),
    ("Check Point Research", "チェック・ポイント・リサーチ"),
    ("AhnLab ASEC", "アンラボASEC"),
    ("Elastic Security Labs", "エラスティックセキュリティラボ"),
    ("Winnti Group", "Winntiグループ"),
    ("South Korea-aligned", "韓国系"),
    ("JPCERT/CC", "JPCERTコーディネーションセンター"),
    ("WPS Office", "WPSオフィス"),
    ("Atomic Stealer", "Atomic情報窃取型マルウェア"),
    ("Rust Loader", "Rustローダー"),
    ("NetSarang", "ネットサラン"),
    ("FishMonger", "フィッシュモンガー"),
    ("I-SOON", "アイ・スーン"),
    ("ScatterBee", "スキャタービー"),
    ("Flashpoint", "フラッシュポイント"),
    ("Broadcom", "ブロードコム"),
    ("Mandiant", "マンディアント"),
    ("Microsoft", "マイクロソフト"),
    ("Kaspersky", "カスペルスキー"),
    ("Cyfirma", "サイファーマ"),
    ("ESET", "イーセット"),
    ("PwC", "プライスウォーターハウスクーパース"),
    ("Casper", "キャスパー"),
    ("Toshiba", "東芝"),
    (
        "Under the Pure Curtain: From RAT to Builder to Coder",
        "Pureの内幕：RAT、ビルダー、コーダー",
    ),
    (
        "Impersonation, Click Hijacking, and TDS: "
        "Inside a Malware Distribution Ecosystem",
        "なりすまし、クリックハイジャック、TDS："
        "マルウェア配布エコシステムの内側",
    ),
    (
        "Spy group exploits WPS Office zero day; "
        "analysis uncovers a second vulnerability",
        "スパイ集団がWPS Officeゼロデイを悪用、"
        "解析で第二の脆弱性を発見",
    ),
    (
        "Spy group exploits WPS Office zero day; "
        "解析 uncovers a second vulnerability",
        "スパイ集団がWPS Officeゼロデイを悪用、"
        "解析で第二の脆弱性を発見",
    ),
    (
        "Attack Exploiting Legitimate Service by APT-C-60",
        "APT-C-60による正規サービス悪用攻撃",
    ),
    (
        "Update on Attacks by Threat Group APT-C-60 in 2026",
        "脅威グループAPT-C-60による2026年の攻撃の続報",
    ),
    (
        "Update on Attacks by Threat Group APT-C-60",
        "脅威グループAPT-C-60による攻撃の続報",
    ),
    (
        "PureHVNC Deployed via Python Multi-stage Loader",
        "Python多段ローダーで配布されるPureHVNC",
    ),
    (
        "New Loader Executing TorNet and PureHVNC",
        "TorNetとPureHVNCを実行する新型ローダー",
    ),
    (
        "April 2026 Infostealer Trend Report",
        "2026年四月の情報窃取型マルウェア動向報告",
    ),
    (
        "Remus Stealer: A New, Not-So-New Infostealer",
        "Remus Stealer：新しいようで新しくない情報窃取型マルウェア",
    ),
    (
        "APT41: A Dual Espionage and Cyber Crime Operation",
        "APT41：諜報とサイバー犯罪を兼ねる二重作戦",
    ),
    (
        "Winnti Group targeting universities in Hong Kong",
        "香港の大学を標的とするWinnti Group",
    ),
    ("ShadowPad in corporate networks", "企業ネットワーク内のShadowPad"),
    ("Operation FishMedley", "FishMedley作戦"),
    (
        "SPECTRALVIPER and DONUTLOADER using REF2754 activity",
        "SPECTRALVIPERとDONUTLOADERを用いたREF2754活動",
    ),
    ("Check Point Research", "チェック・ポイント・リサーチ"),
    ("Palo Alto Networks Unit 42", "パロアルトネットワークスUnit 42"),
    ("Microsoft Digital Crimes Unit", "マイクロソフトデジタル犯罪対策部門"),
    ("Elastic Security Labs", "エラスティックセキュリティラボ"),
    ("IIJ Security Diary", "IIJセキュリティ日誌"),
    ("NHS England", "英国NHS"),
    ("Secret Blizzard", "シークレット・ブリザード"),
    ("Storm-1919", "ストーム-1919"),
    ("Palo Alto Unit 42", "パロアルトネットワークスUnit 42"),
    ("Check Point", "チェック・ポイント"),
    ("Atomic macOS Stealer", "macOS向け情報窃取型マルウェアAMOS"),
    ("Local PureHVNC analysis results", "PureHVNCローカル解析結果"),
    ("Local RemusStealer analysis results", "RemusStealerローカル解析結果"),
    ("Local ShadowPad analysis results", "ShadowPadローカル解析結果"),
    ("Reviewed batches", "精査したバッチ"),
    ("Result matrix", "結果一覧"),
    ("OSINT details", "公開情報の詳細"),
    ("OSINT detail", "公開情報の詳細"),
    ("OSINT", "公開情報"),
    ("MaaS", "サービス型マルウェア"),
    ("VX-Underground batch", "VX-Underground バッチ"),
    ("version", "バージョン"),
    ("high false-positive risk", "高い誤検知リスク"),
    ("medium false-positive risk", "中程度の誤検知リスク"),
    ("low false-positive risk", "低い誤検知リスク"),
    ("false-positive risk", "誤検知リスク"),
    ("certificate validity", "証明書の有効期間"),
    ("exfiltration/C2", "情報持ち出し／指令制御（C2）"),
    ("static extraction incomplete", "静的抽出未完了"),
    ("none recovered", "復元なし"),
    ("static configuration", "静的設定"),
    ("configuration extraction", "設定抽出"),
    ("confirmed static configuration", "確認済み静的設定"),
    ("confirmed C2", "確認済み指令制御（C2）先"),
    ("C2 infrastructure", "指令制御（C2）基盤"),
    ("C2 endpoint", "指令制御（C2）先"),
    ("C2 availability", "指令制御（C2）先の稼働状況"),
    ("C2 check-in", "指令制御（C2）チェックイン"),
    ("command and control", "指令制御"),
    ("family attribution", "ファミリ帰属"),
    ("malware family", "マルウェアファミリ"),
    ("payload configuration", "ペイロード設定"),
    ("process image", "プロセスイメージ"),
    ("delivery stage", "配信段階"),
    ("delivery stages", "配信段階"),
    ("final payload", "最終ペイロード"),
    ("inner payload", "内部ペイロード"),
    ("recovered payload", "復元ペイロード"),
    ("recovered layer", "復元層"),
    ("recovered layers", "復元層"),
    ("literal-only", "文字列だけの"),
    ("literal infrastructure", "文字列として現れる基盤"),
    ("public source", "公開情報源"),
    ("primary source", "一次情報源"),
    ("static evidence", "静的根拠"),
    ("dynamic analysis", "動的解析"),
    ("static analysis", "静的解析"),
    ("technical analysis", "技術解析"),
    ("infection chain", "感染チェーン"),
    ("behavior model", "挙動モデル"),
    ("behavior and configuration", "挙動と設定"),
    ("packing and attribution", "パッキングと帰属"),
    ("decryption and configuration", "復号と設定"),
    ("request paths", "要求パス"),
    ("campaign user ID", "キャンペーン利用者ID"),
    ("external-IP discovery", "外部IPの確認"),
    ("custom RC4 key", "独自ストリーム暗号（RC4）鍵"),
    ("repeating XOR", "反復排他的論理和"),
    ("encoded SHA-256", "符号化物のハッシュ値（SHA-256）"),
    ("recovered PE SHA-256", "復元実行形式のハッシュ値（SHA-256）"),
    ("submitted SHA-256", "提出物のハッシュ値（SHA-256）"),
    ("exact hash", "完全一致ハッシュ"),
    ("high confidence", "高信頼度"),
    ("medium confidence", "中信頼度"),
    ("low confidence", "低信頼度"),
    ("not performed", "未実施"),
    ("not contacted", "未接続"),
    ("was not contacted", "接続していません"),
    ("were not contacted", "接続していません"),
    ("was not executed", "実行していません"),
    ("were not executed", "実行していません"),
    ("not executed", "未実行"),
    ("not confirmed", "未確認"),
    ("not recovered", "未復元"),
    ("not available", "利用不能"),
    ("rather than", "ではなく"),
    ("instead of", "ではなく"),
    ("because of", "のため"),
    ("based on", "に基づく"),
    ("as well as", "に加えて"),
    ("at least", "少なくとも"),
    ("as with", "と同様に"),
    ("does not", "しません"),
    ("do not", "しません"),
    ("did not", "しませんでした"),
    ("cannot", "できません"),
    ("can be", "となる可能性があります"),
    ("may be", "である可能性があります"),
    ("must be", "である必要があります"),
    ("should be", "であるべきです"),
    ("is treated as", "として扱います"),
    ("are treated as", "として扱います"),
    ("is excluded", "除外します"),
    ("are excluded", "除外します"),
    ("is retained", "保持します"),
    ("are retained", "保持します"),
    ("is confirmed", "確認済みです"),
    ("are confirmed", "確認済みです"),
    ("was performed", "実施しました"),
    ("were performed", "実施しました"),
    ("was recovered", "復元しました"),
    ("were recovered", "復元しました"),
    ("current liveness", "現在の稼働状況"),
    ("server ownership", "サーバー所有者"),
    ("password guessing", "パスワード推測"),
    ("password-protected", "パスワード保護された"),
    ("in-memory", "メモリ内"),
    ("memory-only", "メモリ内のみの"),
    ("run key", "自動実行キー"),
    ("run-key", "自動実行キー"),
    ("parent/child", "親子"),
    ("browser databases", "ブラウザーデータベース"),
    ("credential-store", "認証情報保管領域"),
    ("network context", "ネットワーク文脈"),
    ("environment tuning", "環境調整"),
    ("starting points", "出発点"),
    ("present ownership", "現在の所有者"),
    ("private address", "プライベートアドレス"),
    ("false positives", "誤検知"),
    ("false negatives", "検知漏れ"),
    ("publishable Internet", "公開可能なインターネット"),
    ("proof that", "ことの証拠"),
    ("no raw", "未加工物を含まず"),
    ("offline assessment", "オフライン評価"),
    ("passive-query generation", "受動問い合わせ生成"),
)


_WORDS: dict[str, str] = {
    "a": "", "an": "", "the": "", "and": "と", "or": "または",
    "but": "ただし", "if": "場合", "when": "時", "while": "一方",
    "because": "ため", "therefore": "したがって", "than": "より",
    "as": "として", "of": "の", "to": "へ", "from": "から",
    "in": "内", "on": "上", "at": "で", "by": "により",
    "for": "向け", "with": "とともに", "without": "なしで",
    "through": "を通じて", "under": "配下", "inside": "内部",
    "outside": "外部", "before": "前", "after": "後", "between": "間",
    "this": "この", "that": "その", "these": "これら", "those": "それら",
    "it": "これは", "its": "その", "they": "それら", "their": "それらの",
    "is": "です", "are": "です", "was": "でした", "were": "でした",
    "be": "である", "been": "である", "being": "である",
    "not": "ない", "no": "ありません", "none": "なし", "only": "のみ",
    "also": "また", "still": "依然として", "already": "すでに",
    "can": "可能", "could": "可能", "may": "可能性があります",
    "might": "可能性があります", "must": "必要", "should": "推奨",
    "will": "予定", "would": "想定",
    "has": "持ちます", "have": "持ちます", "had": "持っていました",
    "uses": "使用します", "use": "使用", "used": "使用済み",
    "contains": "含みます", "contain": "含む", "contained": "含まれます",
    "requires": "必要とします", "require": "必要", "required": "必要",
    "remains": "残ります", "remain": "残る", "retained": "保持済み",
    "recovered": "復元済み", "recover": "復元", "decoded": "復号済み",
    "decrypts": "復号します", "decrypted": "復号済み", "decryption": "復号",
    "encrypted": "暗号化された", "encoded": "符号化された",
    "confirmed": "確認済み", "reviewed": "精査済み",
    "inferred": "推定", "observed": "観測済み", "recorded": "記録済み",
    "performed": "実施済み", "executed": "実行済み", "contacted": "接続済み",
    "submitted": "提出済み", "stored": "保存済み", "written": "書き込み済み",
    "tested": "検証済み", "matched": "一致済み", "matches": "一致します",
    "matching": "一致する", "combine": "組み合わせる",
    "combines": "組み合わせます", "correlate": "相関させる",
    "correlation": "相関", "promoted": "昇格済み", "excluded": "除外済み",
    "separated": "分離済み", "parsed": "解析済み", "analyzed": "解析済み",
    "statically": "静的に", "independently": "独立して",
    "current": "現在の", "recent": "最近の", "new": "新しい",
    "same": "同じ", "other": "別の", "generic": "一般的な",
    "specific": "固有の", "proprietary": "独自の", "custom": "独自の",
    "exact": "完全一致の", "probable": "可能性が高い",
    "possible": "可能な", "available": "利用可能",
    "unavailable": "利用不能", "complete": "完了",
    "incomplete": "未完了", "unresolved": "未解決",
    "unknown": "未識別", "legitimate": "正規の", "malicious": "悪性の",
    "high": "高", "medium": "中", "low": "低", "final": "最終",
    "inner": "内部", "outer": "外部", "plaintext": "平文",
    "literal": "文字列", "static": "静的", "dynamic": "動的",
    "analysis": "解析", "research": "調査", "review": "精査",
    "result": "結果", "results": "結果", "coverage": "対象範囲",
    "identity": "識別情報", "behavior": "挙動", "configuration": "設定",
    "config": "設定", "structure": "構造", "layout": "配置",
    "format": "形式", "module": "モジュール", "plugin": "プラグイン",
    "family": "ファミリ", "attribution": "帰属", "evidence": "根拠",
    "confidence": "信頼度", "status": "状態", "context": "文脈",
    "limitation": "制約", "limitations": "制約", "assessment": "評価",
    "detection": "検知", "signature": "シグネチャ", "rule": "ルール",
    "rules": "ルール", "indicator": "指標", "indicators": "指標",
    "risk": "リスク", "candidate": "候補", "candidates": "候補",
    "sample": "検体", "samples": "検体", "artifact": "成果物",
    "artifacts": "成果物", "payload": "ペイロード", "loader": "ローダー",
    "loaders": "ローダー", "dropper": "ドロッパー", "packer": "パッカー",
    "packers": "パッカー", "wrapper": "ラッパー", "wrappers": "ラッパー",
    "layer": "層", "layers": "層", "stage": "段階", "stages": "段階",
    "delivery": "配信", "deliveries": "配信物", "submission": "投稿物",
    "submissions": "投稿物", "file": "ファイル", "files": "ファイル",
    "directory": "ディレクトリ", "path": "パス", "paths": "パス",
    "resource": "リソース", "resources": "リソース", "section": "セクション",
    "sections": "セクション", "byte": "バイト", "bytes": "バイト",
    "string": "文字列", "strings": "文字列", "value": "値", "values": "値",
    "key": "鍵", "keys": "鍵", "seed": "シード", "cipher": "暗号",
    "algorithm": "アルゴリズム", "compression": "圧縮",
    "entropy": "エントロピー", "password": "パスワード",
    "archive": "アーカイブ", "archives": "アーカイブ",
    "image": "イメージ", "process": "プロセス", "execution": "実行",
    "injection": "注入", "persistence": "永続化", "service": "サービス",
    "host": "ホスト", "server": "サーバー", "client": "クライアント",
    "endpoint": "接続先", "endpoints": "接続先", "infrastructure": "基盤",
    "network": "ネットワーク", "transport": "通信方式",
    "protocol": "プロトコル", "port": "ポート", "ports": "ポート",
    "domain": "ドメイン", "address": "アドレス",
    "resolver": "名前解決先", "request": "要求", "requests": "要求",
    "response": "応答", "liveness": "稼働状況", "ownership": "所有者",
    "provider": "提供元", "providers": "提供元", "certificate": "証明書",
    "reference": "参照", "references": "参照",
}
_WORDS.update({
    "campaign": "キャンペーン", "operator": "運用者", "group": "グループ",
    "actor": "攻撃主体", "attack": "攻撃", "attacks": "攻撃",
    "activity": "活動", "operation": "作戦", "target": "標的",
    "targets": "標的", "targeting": "標的化", "threat": "脅威",
    "security": "セキュリティ", "malware": "マルウェア",
    "stealer": "情報窃取型", "infostealer": "情報窃取型",
    "rat": "遠隔操作型マルウェア", "bot": "ボット",
    "command": "コマンド", "commands": "コマンド", "control": "制御",
    "download": "ダウンロード", "upload": "アップロード",
    "screenshot": "画面取得", "extension": "拡張子",
    "browser": "ブラウザー", "wallet": "ウォレット",
    "wallets": "ウォレット", "credential": "認証情報",
    "credentials": "認証情報", "mutex": "ミューテックス",
    "runtime": "実行環境", "software": "ソフトウェア",
    "tool": "ツール", "tooling": "ツール群", "code": "コード",
    "repository": "リポジトリ", "environment": "環境",
    "version": "バージョン", "versions": "バージョン",
    "builder": "ビルダー", "build": "ビルド", "collection": "収集",
    "set": "集合", "case": "ケース", "cases": "ケース",
    "report": "報告", "reports": "報告", "source": "情報源",
    "sources": "情報源", "public": "公開", "local": "ローカル",
    "external": "外部", "internal": "内部", "active": "能動的",
    "passive": "受動的", "access": "アクセス", "user": "利用者",
    "account": "アカウント", "accounts": "アカウント",
    "generation": "生成", "schedule": "予定", "impersonation": "なりすまし",
    "distribution": "配布", "ecosystem": "エコシステム",
    "vulnerability": "脆弱性", "exploit": "悪用",
    "exploits": "悪用します", "exploiting": "悪用する",
    "protection": "保護", "protected": "保護された",
    "guessing": "推測", "proof": "証拠", "corroboration": "裏付け",
    "own": "所有する", "alone": "単独", "common": "一般的",
    "often": "多くの場合", "commonly": "通常", "usually": "通常",
    "never": "一度もない", "several": "複数の", "multiple": "複数の",
    "single": "単一の", "one": "一つ", "two": "二つ", "three": "三つ",
    "four": "四つ", "six": "六つ", "ten": "十",
    "first": "最初の", "second": "二番目の", "later": "後続の",
    "per": "ごと", "each": "各", "all": "すべて", "any": "任意の",
    "more": "より多く", "most": "大半", "over": "超",
    "into": "へ", "out": "外へ", "up": "上へ", "original": "元の",
    "normalized": "正規化済み", "durable": "持続的な",
    "short-lived": "短命な", "broad": "広範な", "unusual": "異常な",
    "unsigned": "未署名の", "native": "ネイティブ",
    "opaque": "不透明な", "owner": "所有者", "answered": "応答済み",
    "exposes": "公開します", "reading": "読み取り",
    "writes": "書き込み", "loads": "読み込み", "loading": "読み込み",
    "installs": "導入します", "install": "導入", "installed": "導入済み",
    "creates": "作成します", "create": "作成", "generated": "生成済み",
    "produced": "生成済み", "provides": "提供します", "provide": "提供",
    "labels": "ラベル付けします", "label": "ラベル",
    "records": "記録します",
    "focus": "注目", "focuses": "注目します", "indicate": "示す",
    "indicates": "示します", "appear": "見えます", "appears": "見えます",
    "share": "共有", "shares": "共有します", "vary": "変化します",
    "varying": "変化する", "change": "変更", "changes": "変更",
    "different": "異なる", "distinct": "区別された",
    "separate": "分離", "together": "まとめて", "level": "水準",
    "date": "日付", "time": "時刻", "historical": "過去の",
    "present": "現在の", "global": "全体", "globaly": "全体",
    "internet": "インターネット", "private": "プライベート",
    "corporate": "企業", "enterprise": "企業", "administrative": "管理用",
    "automation": "自動化", "deployment": "配備", "migration": "移行",
    "backup": "バックアップ", "inventory": "棚卸し",
    "database": "データベース", "databases": "データベース",
    "store": "保管領域", "stores": "保管領域", "document": "文書",
    "documents": "文書", "system": "システム", "information": "情報",
    "data": "データ", "macro": "マクロ", "script": "スクリプト",
    "scripts": "スクリプト", "interpreter": "インタープリター",
    "parent": "親", "child": "子", "binary": "バイナリ",
    "executable": "実行ファイル", "imports": "インポート",
    "entrypoint": "開始地点", "framing": "フレーミング",
    "stream": "ストリーム", "block": "ブロック", "ciphertext": "暗号文",
    "root": "ルート", "core": "中核", "base": "基底",
    "metadata": "メタデータ", "marker": "マーカー", "markers": "マーカー",
    "shape": "形状", "variant": "亜種", "variants": "亜種",
    "technique": "手法", "techniques": "手法", "method": "方式",
    "methods": "方式", "logic": "処理", "flow": "流れ",
    "chain": "チェーン", "artifacts": "成果物", "material": "重要な",
    "object": "オブジェクト", "objects": "オブジェクト",
    "decoy": "おとり", "sideload": "サイドロード", "sideloading": "サイドロード",
    "pivots": "追跡軸", "availability": "稼働状況",
    "passwords": "パスワード", "guess": "推測", "guessed": "推測済み",
    "verification": "検証", "verify": "検証", "validation": "検証",
    "contact": "接続", "lifetime": "有効期間", "sinkholing": "シンクホール化",
    "expiration": "期限切れ", "reassignment": "再割当",
    "ownership": "所有者", "provenance": "来歴",
})
_TRANSLATIONS = {
    source.casefold(): target
    for source, target in (*_WORDS.items(), *_PHRASES)
}
_TRANSLATION_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    + "|".join(
        re.escape(source)
        for source in sorted(_TRANSLATIONS, key=len, reverse=True)
    )
    + r")(?![A-Za-z0-9_])",
    re.IGNORECASE,
)


_INLINE_CODE = re.compile(r"(`+)([^\r\n]*?)\1")
_BARE_URL = re.compile(r"https?://[^\s<>)]+")
_MARKDOWN_DESTINATION = re.compile(r"(?<=\]\()[^\r\n)]+(?=\))")
_LONG_HASH = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,}(?![0-9A-Fa-f])")
_TECHNICAL_ENUM = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+\b")
_TECHNICAL_FILENAME = re.compile(
    r"\b[A-Za-z0-9_.-]+\.(?:json|ya?ml|md|ps1|py|exe|dll|bin|zip|csv)\b",
    re.I,
)
_DOTTED_IDENTIFIER = re.compile(
    r"\b[A-Za-z_$<>][A-Za-z0-9_$<>]*(?:\.[A-Za-z_$<>][A-Za-z0-9_$<>]*)+\b"
)
_REPOSITORY_IDENTIFIER = re.compile(r"\b(?:AI-security-analysis|VX-Underground)\b")
_HEX_LITERAL = re.compile(r"(?<![A-Za-z0-9])0x[0-9A-Fa-f]+", re.I)
_ISO_TIMESTAMP = re.compile(
    r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z\b"
)
_TECHNICAL_IDENTIFIER = re.compile(
    r"(?<![A-Za-z0-9])(?:C2|RC4|SHA-256)(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_WINDOWS_PATH = re.compile(r"(?:[A-Za-z]:\\|%[A-Za-z0-9_]+%\\)[^\s,;|`]+")
_FENCE = re.compile(r"^\s*(?:`{3,}|~{3,})")
_JAPANESE_GAP = re.compile(
    r"(?<=[\u3000-\u30ff\u3400-\u9fff]) +"
    r"(?=[\u3000-\u30ff\u3400-\u9fff])"
)


def _margins(line: str) -> tuple[str, str, str]:
    leading = line[: len(line) - len(line.lstrip())]
    body_with_end = line[len(leading):]
    trailing = body_with_end[len(body_with_end.rstrip()):]
    body = (
        body_with_end[: len(body_with_end) - len(trailing)]
        if trailing
        else body_with_end
    )
    return leading, body, trailing


def _protected_spans(line: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for pattern in (
        _INLINE_CODE,
        _BARE_URL,
        _MARKDOWN_DESTINATION,
        _LONG_HASH,
        _TECHNICAL_ENUM,
        _TECHNICAL_FILENAME,
        _DOTTED_IDENTIFIER,
        _REPOSITORY_IDENTIFIER,
        _HEX_LITERAL,
        _ISO_TIMESTAMP,
        _TECHNICAL_IDENTIFIER,
        _WINDOWS_PATH,
    ):
        spans.extend(match.span() for match in pattern.finditer(line))
    spans.sort()
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start < merged[-1][1]:
            old_start, old_end = merged[-1]
            merged[-1] = (old_start, max(old_end, end))
        else:
            merged.append((start, end))
    return merged


def _translate_plain(segment: str) -> str:
    segment = _TRANSLATION_PATTERN.sub(
        lambda match: _TRANSLATIONS[match.group(0).casefold()],
        segment,
    )
    segment = re.sub(r" {2,}", " ", segment)
    return _JAPANESE_GAP.sub("", segment)


def _translate_outside_protected(line: str) -> str:
    pieces: list[str] = []
    cursor = 0
    for start, end in _protected_spans(line):
        pieces.append(_translate_plain(line[cursor:start]))
        pieces.append(line[start:end])
        cursor = end
    pieces.append(_translate_plain(line[cursor:]))
    return "".join(pieces)


def translate_line(line: str) -> str:
    """1行を翻訳し、保護対象と前後の空白・改行を維持する。"""

    if _FENCE.match(line):
        return line
    leading, body, trailing = _margins(line)
    translated = _EXACT.get(body, body)
    return leading + _translate_outside_protected(translated) + trailing
