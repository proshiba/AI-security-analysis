# AsyncRAT候補2件の追加静的監査（2026-09-22）

## 対象と判定境界

| SHA-256 | 元検体の再照合 | 内部ファミリー判定 | 設定・C2 | 未完了の中心 |
|---|---|---|---|---|
| `00180c06765fed73c87dec265fb389be957c9fdca36bd3b00f8c421e812631e2` | 手元の元検体をSHA-256と90,624バイトで再照合 | AsyncRATを静的確認済み | 設定とC2 1件を静的確認済み。稼働は未確認 | 挙動欄と全体フロー文書への反映不足 |
| `5e84fd9106777b85d5a60f4e607940730ba57ea2dcafaeaaadd6f21e38555761` | 手元の元検体を発見できず。過去の保管検証記録は存在 | 提供元のAsyncRAT報告のみ。内部確認なし | 設定・C2とも未確認 | 保護層内の終端payload未復元 |

本監査は検体の実行、C2接続、任意のGhidraスクリプトを行っていない。上記のどちらも、国内での感染端末や感染経路が当該ハッシュと直接結び付く資料は確認していない。提供元での検体発見日を国内の感染日と読み替えない。

## `00180c06...`：終端clientは既に回収済み

元検体のSHA-256を再計算し、[ケース概要](../../../malware/asyncrat/versions/unknown/cases/00180c06765fed73c87dec265fb389be957c9fdca36bd3b00f8c421e812631e2/README.md)の値と一致することを確認した。過去の[関数単位解析](../../../malware/asyncrat/versions/unknown/cases/00180c06765fed73c87dec265fb389be957c9fdca36bd3b00f8c421e812631e2/STATIC-LOGIC.md)には210 managed methodのinventoryと代表13 methodの静的レビューがあり、CILから設定復号・通信・dispatcherまで追跡している。新たな逆コンパイルをしたという意味ではない。

- 設定はChaCha20で難読化され、版は`0.5.8`、groupは`Default`、`Install=false`、anti-analysis設定は`false`。[設定記録](../../../malware/asyncrat/versions/unknown/cases/00180c06765fed73c87dec265fb389be957c9fdca36bd3b00f8c421e812631e2/analysis.json)と[handler証拠](../../../malware/asyncrat/versions/unknown/cases/00180c06765fed73c87dec265fb389be957c9fdca36bd3b00f8c421e812631e2/handler-results.json)が対応する。`Install=false`はこの設定でインストール分岐が有効ではないことを示すが、実行時の永続化を動的に否定するものではない。
- 静的設定上のC2は`rororo2323[.]bounceme[.]net:1533`の1件。[通信パターン](../../../malware/asyncrat/versions/unknown/cases/00180c06765fed73c87dec265fb389be957c9fdca36bd3b00f8c421e812631e2/communication-patterns.json)は`TLS`、4バイトlittle-endian長、MessagePackを静的に確認している。実C2の応答・稼働、現在のDNS解決先は本監査で確認していない。
- `Main`はAssemblyResolve/TLS設定を初期化し、.NET 4.8欠如時にMicrosoft配布installerを`/q /norestart`で起動する分岐を持つ。これは条件付きの正規前提ソフト導入経路で、通常起動時に必ず子プロセスを作るとの観測ではない。その後の遅延、設定復号、TCP/TLS接続への移行はCILレビューで確認されている。
- 登録MessagePackの`T=ci`、heartbeatの`T=hb`、返信`hbr`、受信時の`wu`・`sp`・`sv`分岐、受領managed pluginを`Plugin.Plugin.Run`へ反射呼出しする経路が関数レビューにある。これはコード上の能力であり、この検体で各C2コマンドが実際に届いた証拠ではない。受領コードの実行もしていない。

[FEATURES.md](../../../malware/asyncrat/versions/unknown/cases/00180c06765fed73c87dec265fb389be957c9fdca36bd3b00f8c421e812631e2/FEATURES.md)は`behavior_not_documented`と記す一方、[STATIC-LOGIC.md](../../../malware/asyncrat/versions/unknown/cases/00180c06765fed73c87dec265fb389be957c9fdca36bd3b00f8c421e812631e2/STATIC-LOGIC.md)には上記の挙動が具体化されている。また[OVERALL-LOGIC.md](../../../malware/asyncrat/versions/unknown/cases/00180c06765fed73c87dec265fb389be957c9fdca36bd3b00f8c421e812631e2/OVERALL-LOGIC.md)は「全体ロジックを構成できませんでした」としている。したがって本件は「終端payload・設定・C2が未解析」ではなく、主に既存の静的証拠を挙動／フロー表示へ正しく反映できていない文書生成上の未完了である。特定の日本国内キャンペーンへの帰属も別途証拠が必要。

## `5e84fd91...`：保護層で停止

[ケース概要](../../../malware/asyncrat/versions/unknown/cases/5e84fd9106777b85d5a60f4e607940730ba57ea2dcafaeaaadd6f21e38555761/README.md)の提供元署名はAsyncRATだが、内部判定は`provider_reported_not_statically_confirmed`。[PE静的要約](../../../malware/asyncrat/versions/unknown/cases/5e84fd9106777b85d5a60f4e607940730ba57ea2dcafaeaaadd6f21e38555761/analysis.json)は3,939,840バイト、entropy 7.7369、`.boot`高entropy、`.themida` section、2 importを記録する。section名だけでThemidaの版や内側のマルウェアを断定しない。`mscoree.dll!_CorExeMain` importはあるが、CLI構造の確認結果は`.NET=false`であり、内側を.NETと断定できない。

[静的レイヤー](../../../malware/asyncrat/versions/unknown/cases/5e84fd9106777b85d5a60f4e607940730ba57ea2dcafaeaaadd6f21e38555761/static-layers.json)ではPE magic候補51件を全域走査し、構造検証で全件棄却した。走査予算の枯渇ではなく、確証のある子PEが0件だった。[handler評価](../../../malware/asyncrat/versions/unknown/cases/5e84fd9106777b85d5a60f4e607940730ba57ea2dcafaeaaadd6f21e38555761/candidate-handler-assessment.json)はAsyncRAT handlerの適用試行1件を記録するが、`no_evidence`で設定なし。[Ghidra由来の代表関数記録](../../../malware/asyncrat/versions/unknown/cases/5e84fd9106777b85d5a60f4e607940730ba57ea2dcafaeaaadd6f21e38555761/STATIC-LOGIC.md)は外側entry point 1件の分岐までで、復号された終端payload、通信関数、プロセス生成、永続化を証明しない。「代表関数解析完了」は「検体の機能解析完了」と同義ではない。

今回のオフライン探索では元検体ファイルを再発見できず、現在接続しているGhidra MCPプロジェクトにも両対象のprogramは存在しなかった。過去の対象別アーカイブにSHA-256・サイズ・暗号化保管の検証記録は残るが、本監査ではネットワークを利用しないため復元していない。次の静的解析は、アーカイブから認証済み元検体を再取得し、ハッシュを検証してから保護層の外側・内側を区別して追跡する必要がある。内側の実体を検証できるまで、AsyncRAT確定、C2確定、国内感染キャンペーンへの関連付けは行わない。
