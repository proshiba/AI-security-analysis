# 国内観測を軸にした8ファミリーの未完了解析（2026-09-22）

## 結論と証拠の境界

指定されたPureRAT、DcRAT、AsyncRAT、VenomRAT、Formbook、LummaStealer、RemusStealer、ValleyRATを、既存の終端ペイロード未取得台帳、個別ケース、国内向け攻撃の一次報告で突合した。現行3,762ケースに台帳を同期した結果、8系統の**終端復元上の未完了は計104ケース**だった。この数値は「解析状態がpartialである全ケース」ではなく、終端payloadまたは終端familyの未取得が明記された集合に限る。ファミリーフォルダーの配置や提供元signatureだけで、各ケースの最終ファミリーや国内配布を確定しない。

国内報告の多くは日本語メールの**送信・配布・検知**の観測であり、受信端末での実感染・侵害成立まで示していない。現行の主検体との完全SHA-256一致は後述するPureRAT配布DLL、復元済み子層との一致はPureLogs報告のmanaged層に限られた。別の未完了ケースへ記事のC2やコマンドを転記しない。検体実行、配布URL接続、C2接続は行っていない。

| 系統 | 終端復元ギャップ | 国内根拠の性質 | 本調査での扱い |
|---|---:|---|---|
| PureRAT／PureHVNC | 3 | 2026年7～8月の日本語メールと配布物を一次解析が報告 | 完全一致する別の配布DLLは復元済み。未完了ケースにはPureLogsとの帰属矛盾を発見 |
| DcRAT | 0 | 2023年の国内観光業向け攻撃・被害相談 | 最近の未完了対象としては根拠不足。既存の1ケースは完了状態 |
| AsyncRAT | 3 | 2026年4～6月の日本語メールによる配布を一次解析が報告 | 未完了の最新ケースは提供元ラベルのみで、記事の検体との同一性なし |
| VenomRAT | 8 | 2026年6月の日本語請求書メールを一次解析が報告 | 記事の悪性DLLは現行catalogに未登録。内部帰属済みの別ケースも設定・C2が未解決 |
| Formbook | 11 | 2026年4～6月の日本語注文書メールを一次解析が報告 | 別の未完了PEをGhidraで追加静的解析。記事のJSとの同一性なし |
| LummaStealer | 16 | 2025年5月の国内製品検知。一般的な感染経路としてClickFixも報告 | 国内検知と個別ケースの一致は未立証。保護層・最終設定の再調査対象 |
| RemusStealer | 22 | 最近の国内感染を特定できる一次資料は今回未確認 | 地域仮説で優先順位を上げず、終端復元・内部帰属を先行 |
| ValleyRAT | 41 | 2025年末～2026年の国内向け日本語メールを複数の一次解析が報告 | 既存の国内キャンペーンと未完了の別ケースを分離。Inno検体1件の暗号化子4件を静的復元 |

件数の正本は[終端ペイロード未取得台帳](../../../../intelligence/terminal-payload-recovery/README.md)と[inventory.json](../../../../intelligence/terminal-payload-recovery/inventory.json)。本調査時に台帳の旧3,662ケース／1,013件を3,762ケース／1,015件へ更新し、`--check`で一致を確認した。増加した2件は未分類であり、上表の8系統の件数は変わっていない。

## 国内報告と手元検体の照合

- [ITOCHU Cyber & IntelligenceのPureRAT／PureLogs解析（2026-09-04）](https://blog.itochuci.co.jp/entry/2026/09/04/130000)は、破損・返金を装う日本語メールから偽共有ページ、ZIP、署名済みExcelとDLLサイドロード、Donut、PureRATまたはPureLogsまでを分析している。悪性DLL `e55412555b4699c6d3ce2ac60df81eb1ee0d5aa412a303555c8f64037d5633d0` は[既存の復元済みPureRATケース](../../../malware/purehvnc/versions/v4.4.1/cases/e55412555b4699c6d3ce2ac60df81eb1ee0d5aa412a303555c8f64037d5633d0/README.md)と完全一致する。そのケースのC2設定は**このハッシュに限る**。
- 同記事は `.NET` SHA-256 `af4ee79582992e348a8739579da478d50daccbaa6ec97420311916a2ac0fc503` を、異なる2つのローダー経路で共有される**PureLogs**と記載する。この値は[未完了の`a4a0b87c...`ケース](../../../malware/purehvnc/versions/unknown/cases/a4a0b87c94132e0433ae48e2151f31e8cdb02113cd0f3aa81a903adc854a64d9/README.md)がDonutから復元したmanaged層のSHA-256と完全一致する。同ケースを「PureRAT終端」と解釈すると矛盾する。ローダーのPureブランド系統と終端ファミリーを分離し、PureLogs帰属を**外部のexact-hash報告による有力候補**として再評価する。さらに内包された終端assemblyの実method bodyはまだ復元できず、その設定・C2・版を確定しない。
- [ITOCHUの2026年4～6月日本語メール調査（2026-09-04）](https://blog.itochuci.co.jp/entry/2026/09/04/110000)はFormbook、ValleyRAT、VenomRAT、AsyncRATの配布例を載せる。ただし記事中のFormbook JS `f37f4c5796330bdf008cd7849c9411e9542989ee6be30903a8c5631f736b6bfd`、ValleyRAT `PDFCORE8.dll` `8d0d4b139440550dfa7bd031be9e71bab3a5feed36a2f8ba59c0eddc3a9c39e4`、VenomRAT `nvdaHelperRemote.dll` `abd52fb018452565493d51b89d27d9ed16d94a0db709d35d104bec240a04d90a` は、現行`catalog/cases.json`の主検体SHA-256とは一致しない。類似の配布名やファミリー名だけで既存ケースを同じ活動へ結ばない。
- [同社のValleyRAT日本語メール調査（2026-04-03）](https://blog.itochuci.co.jp/entry/2026/04/03/133000)と上記の続報は、配布方法・基盤が複数あることを示す。ValleyRAT利用を単一のSilver Fox活動へ一括帰属しない。リポジトリ内の[2026年8月の国内向け3件](../../campaigns/valleyrat-japanese-malspam-20260820/README.md)も、個別のサイドロード関係と検体ハッシュを正本とする。
- [キヤノンMJの国内ESET検知統計（2025-06-26）](https://eset-info.canon-its.jp/malware_info/malware_topics/detail/malware2505.html)は国内でのLumma検出を示し、ClickFixを一般的な感染経路の一つとして説明する。ただし、現在の16未完了ケースが国内検知対象またはClickFix配布物だったとは言えない。
- [ラックの国内観光業向け調査（2023-10-23）](https://www.lac.co.jp/lacwatch/alert/20231023_003546.html)はDcRATの国内利用を示すが、今回の「最近」条件には古い。RemusStealerについては、調査した一次資料から最近の国内配布物・受信端末感染を特定できなかった。

## 静的解析で追加確認した未完了ケース

### Formbook報告ケース `eee434a0...`

[2026-09-16観測ケース](../../../malware/formbook/versions/unknown/cases/eee434a01829c957c266fab72279ef491fbca7592236f1885d4f03e2d1e72a4d/README.md)の隔離済みPEと元ZIPを既存報告SHA-256で照合した。PEは285,696バイト、元ZIPのSHA-256は`5451f6d9cab06e927809834ea1800724f2b881064e5635e0856dc1ff6d6748ad`。x86 PEの高entropyな`.text`、import 0、4つの埋込PEらしいmagicの構造検証失敗、復元子0という既存結果を確認した。Ghidra MCPで既存programを明示選択し、`FUN_00401080`とentry側の間接callを追加調査した。`FUN_00401080`には`0x99` XORで局所bufferを作り、対象領域の`0x24`バイトを退避・一時上書きして間接call後に復元する経路がある。これは一時的なコード差し替え／トランポリンの静的証拠であり、復号された最終payloadの証拠ではない。詳細は[追加関数解析](FORMBOOK-EEE-STATIC.md)。内部のFormbook固有構造、終端payload、設定、C2は未確認で、日本語注文書メールのJSとも同一検体ではない。

### ValleyRAT／Gh0stRAT報告ケース `df603ed5...`

[既存ケース](../../../malware/valleyrat/versions/unknown/cases/df603ed55cbf6f9d74068b956ab966a7b785eb102e1045f343d96255eb2cdc24/README.md)のInno Setup原検体をSHA-256で再照合し、暗号化された子4件を**非実行・メモリ内**で復元した。予定される起動順は`hrnnj.exe 64E0938ABD16B4F698CCB0CC011AFB4F`、次に`hftptt.exe`で、前者は同梱`log.dll!GenericLogImpl`をimportする。子ファイルの形式、完全ハッシュ、配置先、地域判定の留保は[Inno内層追補](VALLEY-DF603-STATIC.md)に記録した。既存の`oidng2.duoshit.com`等は子の平文に現れず、外部相関値のままである。ValleyRATとGh0stRATの提供元ラベルの矛盾、終端config・C2は未解決。国内感染との検体照合もない。

### 他の優先停止点

- [AsyncRAT報告`5e84fd91...`](../../../malware/asyncrat/versions/unknown/cases/5e84fd9106777b85d5a60f4e607940730ba57ea2dcafaeaaadd6f21e38555761/README.md)：2026-09-06観測の3,939,840バイトPE。`.boot`の高entropy、Themida marker、import 2、PE候補51件が構造検証で棄却、子層0。AsyncRAT handlerは`no_evidence`で内部familyも未確定。現時点で元検体を再照合できず、追加のbyte解析は保留。
- [Pure系`a4a0b87c...`](../../../malware/purehvnc/versions/unknown/cases/a4a0b87c94132e0433ae48e2151f31e8cdb02113cd0f3aa81a903adc854a64d9/README.md)：AppV DLL→sidecarの回転/XOR→Donut→保護.NET→終端.NETまでは静的復元済み。残るのはresource-backed protectorが再構築するmethod body、実設定、C2、終端帰属。今回のPureLogs exact-hash照合で、従来のPureRAT推定は再評価が必要。
- [VenomRAT`9c8969b2...`](../../../malware/venomrat/versions/unknown/cases/9c8969b2fc30c395e31a4443cc691c889b309f906e69c2f98cdd92adb812b456/README.md)：内部静的帰属は得たが、設定・C2は未解決。記事の日本語請求書ケースと同一ではない。
- [ValleyRAT報告`658fc8b2...`](../../../malware/valleyrat/versions/unknown/cases/658fc8b2caf56d7572f065bdc7bcf248f1ba3e96901ba6ed3eee4291e524d46e/README.md)：2026-09-13観測のPE。提供元ラベルのみでhandler成功0、関数解析が必要。国内配布・ValleyRAT終端・C2はどれも未確認。
- [RemusStealer報告`e2bb1813...`](../../../malware/remusstealer/versions/unknown/cases/e2bb18135f11abb5afa22fcd607183ff5cc5d2d499f8924a9a09dbe32ce7ecb9/README.md)：2026-08-31観測のPE。提供元ラベルのみ、handler成功0、関数解析・終端復元が必要。国内事例への結び付けは保留。
- [LummaStealer報告`009b2025...`](../../../malware/lummastealer/versions/unknown/cases/009b2025c43202f2c643e46d27b30ca5e0f33b7da37841a661838aa07ac34938/README.md)：旧形式成果物の`go_pe_loader`は配布形態ラベルで、Go製であることを関数単位で確認した結果ではない。復元した静的子は0。国内検知統計からこのSHAの感染を推定しない。

追加の既存証拠監査は[AsyncRAT](ASYNCRAT-STATIC.md)、[VenomRAT／ValleyRAT](VENOM-VALLEY-STATIC.md)、[LummaStealer／RemusStealer](LUMMA-REMUS-STATIC.md)に分けて記録した。特にAsyncRAT `00180c06...` は終端・設定・静的C2を既に回収しており、残る主課題は`FEATURES.md`と全体フローへの反映不足である。これは上表の「終端復元ギャップ3件」に含まれない。一方、VenomRAT `9c8969b2...` の動的設定resolverと証明書pinは復元済みでも、実C2 endpointではない。ValleyRAT `658fc8b2...` の`_guard_dispatch_icall`はMSVC Control Flow Guardの補助関数であり、既存要約の「C2命令分配器」という意味付けを採用しない。LummaStealer `009b2025...` の`analysis_assessment.status=complete`は設定・関数未解析と両立しておらず、解析完了の根拠に使わない。

元byteの再探索では、AsyncRATとValleyRATを含む6系統の終端ギャップ90件中、15件に対応するローカル候補を確認した（ValleyRAT整理先13、AsyncRAT整理先2）。AsyncRATの2件とValleyRAT `df603ed5...` は元ハッシュとの一致を検証した。残る候補も個別に照合が必要で、存在だけで終端復元成功とは数えない。上記の代表ケース`5e84...`、`9c896...`、`009b...`、`e2bb...`、`658fc...`の元byteは今回の探索範囲では見つからなかった。

## 次の解析順

1. 国内向け一次報告に記載された完全配布物を、出典とSHA-256で認証してから別ケースとして静的解析する。特にFormbookのZIP／JS、ValleyRATのDOC／DLL、VenomRATのZIP／IMG／DLLを優先する。既存ケースとの同一性を先に仮定しない。
2. 手元にbyteがある`eee434a0...`の一時上書き先、間接call先、復元後の層を静的に追跡する。Formbook固有設定と終端PEが確認できるまで帰属・C2を確定しない。
3. Pure系`a4a0b87c...`の`af4ee795...`一致を既存分類へ反映する前に、PureLogsの実method bodyと構成を確認する。PureRATの`tirakian.com`設定を転記しない。
4. ValleyRAT報告`df603ed5...`の`log.dll`独自節と`Update.xml` binaryを静的に追い、終端familyと設定を検証する。現時点では旧ケースの推定C2を確認済み値へ昇格しない。
5. 国内照合ができていないAsyncRAT、Lumma、Remus、ValleyRATの最新未完了ケースは、元byteの存在とSHA-256を先に検証し、保護層→終端payload→family→config→C2の順に処理する。未取得時は未完了のまま保持する。

本調査の追加静的作業では検体を実行せず、任意Ghidra script、CPU／CLRエミュレーション、ライブC2通信を行っていない。記事掲載の配布URL、C2候補、共有サービスには接続していない。
