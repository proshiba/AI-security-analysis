# アンパック再評価 — 2026-07-15

## 結論

2026-07-15 refresh の9ファミリー・90検体を、検体・復元物を一度も実行せず、外部通信も行わない条件で再評価した。39検体から少なくとも1層を復元した。従来「packed」と見えていたものの大半は、自己解凍形式、リソース格納、配布スクリプト、UPX、AutoIt、または分割ファイルであり、静的に終端層まで処理できた。

ローカルに存在する全レイヤーを対象とした結果、未解決の保護層は5件である。内訳は ValleyRAT の仮想化PE 3件、RemusStealer の独自ネイティブローダー1件、RemcosRAT のNSIS後段ネイティブローダー1件である。これらを「完全アンパック済み」とは扱わない。Vidar 2件は配布URLまでは復元したが、参照先ペイロードが提出物に含まれず、外部取得もしなかったため `missing_external_payload` とする。

## ファミリー別結果

| Family | 検体 | 復元層あり | 外側PEのpacking判定 | 未解決の終端保護層 |
|---|---:|---:|---:|---:|
| AgentTesla | 10 | 1 | 0 | 0 |
| AMOS | 10 | 0 | 0 | 0 |
| Formbook | 10 | 5 | 0 | 0 |
| LummaStealer | 10 | 7 | 0 | 0 |
| RemcosRAT | 10 | 5 | 0 | 1 |
| RemusStealer | 10 | 4 | 1 | 1 |
| ValleyRAT | 10 | 7 | 0 | 3 |
| VenomRAT | 10 | 8 | 0 | 0 |
| Vidar | 10 | 2 | 0 | 0（外部ペイロード欠落2） |
| **合計** | **90** | **39** | **1** | **5** |

「復元層あり」は終端ペイロードの取得を必ずしも意味しない。中間層だけを復元した RemcosRAT 1件を含む。一方、RemcosRAT の別検体にあったUPX層は、231,424バイトのUPX PEから472,064バイトの非packed PEへ正常に復元済みである。

## 今回追加・改善した復元方法

1. RAR4/RAR5をmagicで識別し、展開後のUTF-16スクリプトを再帰解析する。
2. UTF-8 のバイト順マーク、UTF-16 LE/BE のバイト順マーク、ヌルバイト分布による UTF-16 推定を統一する。
3. JavaScriptの整数式だけをASTで限定評価し、数値配列、配列連結、反復Unicode鍵のXOR/減算を静的に再現する。
4. JavaScriptが環境変数へ分割配置するUnicode列を、復元PowerShell内の参照順に再結合する。
5. PowerShellに明示された `char - 19968`、AES-CBC/PKCS7、GZipの変換だけを再現する。PowerShell自体は実行しない。
6. CMDの `echo BASE64 > file` / `>> file` を出力先ごとに再構成する。個々の短い断片は成果物にせず、完成物の構造を検証する。
7. NSISの `IntOp` / `IntFmt %08X` ワード復号、System-plugin call抽出、x64定数伝播、明示的dword XORループを再現する。
8. 高エントロピーだけでパッキングと決めず、インポート、エントリポイントが属するセクション、ファイル上と仮想メモリ上のセクション形状、UPX・NSIS などのマーカーを併用する。仮想化形状は別分類する。
9. 不正または切断された `MZ` 断片を `corrupt_or_truncated` として隔離し、全体バッチを停止させない。

実装は `unpackers/static_unpacker.py`、`unpackers/javascript_obfuscator.py`、`unpackers/javascript_dropper_unpacker.py`、`unpackers/nsis_unpacker.py` に集約した。

## 新たに終端PEまで復元した代表例

### VenomRAT の再評価

| 提出物SHA-256 | 復元チェーン | 終端PE SHA-256 | サイズ | 判定 |
|---|---|---|---:|---|
| `579085581348296ae88419296edc6a8e91acf4463c7994112b5c3f7f3653710e` | UTF-16スクリプト → 数値配列の排他的論理和 → PowerShell → 環境変数366個 → Unicode値から19968減算 | `4246bf9121476cc6fb8d2f69c6263a7b4d31a331bd02dd9a7603e6200fb9725b` | 361,984 | x64 .NET／パッキングなし |
| `48b59f27da42cfe2d3b806a1c71cc8d8fce0441121a17cd8c1b30bf5e35ea776` | RAR5 → 上記スクリプト → 同じPowerShell／PE | `4246bf9121476cc6fb8d2f69c6263a7b4d31a331bd02dd9a7603e6200fb9725b` | 361,984 | x64 .NET／パッキングなし |
| `d7de7d851061a99e6f2ca256aba5badf90778f566fc528db6396a4180901ac26` | UTF-16スクリプト → 反復減算 → PowerShell → 環境変数80個 → AES-CBC復号 → GZip展開 | `16109f93bcddf8dec5e21057f35b3da437d94976f503f45b217232c26b65515e` | 237,568 | x64 .NET／パッキングなし |
| `ad6417ba292c504cb7307ca0c520435739f87908f117cc2423cd4b7e81cc1ac8` | CMD → 約2,000個のBase64断片 → 再結合 | `d6bb84d31d68519e201370f8ccb60d373412573d125f30c5b3090c1ad206d5fd` | 1,216,000 | x86 ネイティブ／パッキングなし |

既存の .NET ビットマップ列走査も再検証した。`7215...` から `7a66395f...`（68,096 バイト）、`6518...` と `165b...` から同一の `3aa8ce5d...`（33,792 バイト）を復元し、いずれも追加のパッキングなしと判定した。

### その他の代表例

- Formbook の .NET ビットマップローダーから `7a09d4c71af5d34d449fc0ba91c8993492828bc5d6a1a3300c3f27df63c56e28`（66,560 バイト、x86 .NET、パッキングなし）を復元した。
- RemusStealer の2件は、自己解凍コンテナ → CAB → AutoIt A3X → RC4 → LZNT1 を通し、同一の終端 PE `a86f0adedfb993195509aa2923204bdccbf0b9e4d59d0f99636de3b0db5b4668`（222,208 バイト、x64、パッキングなし）を復元した。
- LummaStealer は NSIS/Jadoo 分割マニフェストのオフセット、サイズ、連続性を検証して再構成した。
- Vidar 2件はJavaScript文字列配列を静的復号し、`62.60.226.198/uploads/...exe` の配布URLを得た。URLへは接続していない。

## 未解決5件と静的解析の限界

### RemusStealer（`5e815731...`）の再評価

- x64 PE、インポート数0、`.rdata` は228,352バイトでエントロピー7.9942、エントリポイントは高エントロピー領域にある。
- エントリ側で API をハッシュ解決し、約 `0x36400` バイトの読み書き・実行可能領域を確保する。
- Ghidra で復号・メモリローダー候補 `0x140001730` を追跡したが、巨大な独自状態機械であり、単純な定数鍵や既知のパッカーではない。
- 復元済みopaque resource（SHA-256 `9a76e1fd...`）は終端PEではない。
- 未解決要因: `native_control_flow_obfuscation`。安全方針上、検体の実行、ローダースタブの実行、プロセスメモリのダンプ、CPU エミュレーションは行っていない。

### ValleyRAT 3件の再評価

| 提出物 | OLEから復元したPE | サイズ |
|---|---|---:|
| `fc397bf8...` | `db720e674a25318cd09e35d8fae5b43faaa3acf9dfe04f5b6ea23d8c0c414779` | 3,819,008 |
| `ad4a584f...` | `136bdce277b8c810656eccc0b0e4b47f0fde81e1d5aba86a475a08d96b7a22a9` | 3,778,560 |
| `81f68f61...` | `1982d5168c430ee373e6bcbd99322b844bdb5942f778bc9d4b141e7c27182105` | 3,764,736 |

3件は同じ形状の x64 プロテクターで、インポートは `KERNEL32!GetLastError` だけ、通常のセクションはファイル上のサイズが0で、巨大なランダム名の読み取り・実行可能セクションにエントリポイントと高エントロピーのコードがある。Ghidra で代表検体 `ad4a...` を明示的なプログラム指定付きで解析したところ、命令の重なり、不透明な条件分岐、内部サンク、`rdtsc`、スタック状態の操作を持つ仮想化・制御フロー保護を確認した。未解決要因は `native_control_flow_obfuscation` である。

### RemcosRAT（`78b21599...`）の再評価

- NSIS の逆コンパイル結果からワード単位の XOR 鍵 `0x17d68b37` と1,024バイトのコマンド列 `b2d8fcd1...` を復元した。
- システムコールから `Flagskibene` のオフセット6,800に1,482バイトのデコーダー、オフセット8,282に後段があることを確定した。
- x64 の定数伝播により32ビット値の XOR 鍵 `0xe7c94882`、長さ435,824、増分4を特定し、中間ローダー `e9ed0be544b08189ceca2ec8e6ae8f74d62335ed006f0b207fb211df6bbdcb3a` を復元した。
- 復元物は `48 81 ec 65...` で始まるネイティブcontrol-flow-obfuscated loaderで、最終PEではない。blockerは `native_control_flow_obfuscation`。

## 判定と失敗時の確認順

1. マジック値とファイル名を分離して判定する。RAR5、NSIS、UTF-16、OLE、Mach-O を見落とさない。
2. アーカイブ内の一覧、メンバー数の上限、展開総量、パストラバーサル、シンボリックリンク・再解析ポイントを確認する。
3. PE はヘッダー、セクション境界、インポート、エントリポイント、オーバーレイ、リソースを確認する。エントロピーだけでパッキングを断定しない。
4. スクリプトは文字encodingを正規化し、Base64断片の再構成、整数式、配列、Unicode写像、明示された暗号/圧縮の順に限定評価する。
5. 復元物を再帰的に同じpipelineへ渡す。中間UPX/NSIS層を終端と誤認しない。
6. 外部URLが必要なら `missing_external_payload`、runtime状態に鍵が依存するなら `runtime_derived_key`、ネイティブ仮想化なら `native_control_flow_obfuscation` と記録する。

## 検証

- `unpackers/tests`: 21件のテストに合格。
- Ruff によるアンパッカー全体の検査に合格。
- analysis-framework、extractors、unpackers の関連テストスイートは合計84件に合格。
- 90検体のfamily pipelineを再実行し、VenomRATは10件中8件で復元層を確認した。
- pydocを `static_unpacker`、`javascript_obfuscator`、`javascript_dropper_unpacker`、`nsis_unpacker` について再生成した。
- 復元物はローカルのAES暗号化archiveにだけ保存し、Git管理対象にはしていない。
- 全レポートで `sample_executed: false`、`network_contacted: false` を維持した。
