# ValleyRAT C2静的抽出ベンチマーク最終報告（2026-10-28）

## 結論

MalwareBazaarの外部signatureが`ValleyRAT`である新規100件を先に固定し、検体を実行せず、C2・dead-drop・検体内URLへ接続せずに静的解析しました。100件すべてでone-shot解析とdirect-route走査を完了し、ローカル静的解析で2件のC2設定を厳格確認し、3件から候補endpointを復元しました。

| 証拠区分 | 検体数 | 意味 |
|---|---:|---|
| `strict_confirmed` | 2 | 終端ValleyRAT、設定復元、設定からsocket APIまでのlineageが同じ復元チェーンで成立 |
| `candidate` | 3 | 設定builderまたは検証済み設定構造からendpointを復元したが、終端familyまたはsocket lineageが未完了 |
| ローカル自動復元 | 4 | direct-routeまたはhash／size固定manifestから、改良後コードがendpointまで復元 |
| 追加の手動静的復元 | 1 | 同じコード構造を独立追跡してendpointを復元したが、現行parserの自動出力は未完了 |

最初の100件で構造化C2または候補endpointを複数復元できたため、「何も見つからなければ追加100件」という条件は成立せず、2巡目の100件は取得していません。

この母数は外部providerの候補ラベルであり、100件すべてがValleyRATであることを意味しません。したがって、`5/100`をValleyRAT全体のrecallとは解釈しません。exact SHA-256で公開C2報告を確認できた11件に限ると、ローカル静的復元は5件、うち自動復元4件、厳格確定2件でした。公開報告は照合に使っただけで、ローカル設定やfamilyを確定する代替証拠にはしていません。

## 固定集合

- 収集元: MalwareBazaar Community API
- 選定方式: `signature_newest`
- 外部signature: `ValleyRAT`（候補集合の選定にのみ使用）
- 件数: 100件
- first seen範囲: 2026-08-16 13:30:15～2026-10-27 12:02:35
- file type: `exe` 72件、`dll` 20件、`zip` 4件、`msi` 3件、`vhd` 1件
- 集合commitment SHA-256: `bfe69626bcea1b5672aa2e9a1a8a774a9903c9294233bfdc02e49a48f53adb33`
- 過去取得済み6,968 SHA-256を除外し、今回の100件を解析前に固定

100 archiveすべてについて、暗号化状態、archive SHA-256、単一memberのsizeとSHA-256をmanifestへ再照合しました。検体はarchiveからディスクへ平文展開せずにdirect-routeへ渡しています。nested containerの追加解析は、既に静的展開したprivate成果物を親子SHA-256とsizeで再固定して実施しました。

## ローカル復元結果

| 検体SHA-256 | C2 | 区分 | 自動化 | 主な静的根拠 | 未確認点 |
|---|---|---|---|---|---|
| `027b99428c7f640c47cb72632fd8c29ecba9d39c4518993bc5096838ca7b2da2` | `8.218.8.170:443` | `strict_confirmed` | direct-routeで自動 | 一意なreversed vvaS設定、x64 R8 callback、R9 object、vtable、parser出力global、同一WS2 descriptorの`gethostbyname`／`htons`／`connect`、同じsocket fieldのsend／recvを一つの到達可能lineageで証明 | liveness、operator、実行時registry override |
| `01c204a2a9f0989e3abee0f237f6080f2f072467a4d83dd4a4921443a60d09fe` | `137.220.140.19:15443`、`:5555`、`:8888` | `strict_confirmed` | 固定manifest harnessで自動 | NSIS parent → code由来repeating XOR PE → code参照ZipCrypto archive → side-load DLL／sidecar → code参照RC4 terminal PE → reversed vvaS設定 → Winsockを全段SHA-256／sizeで結合 | 通常one-shotの128 MiB安全上限では巨大NSIS仮想memberをmaterializeできないため、前処理済みinventoryが必要 |
| `3b38a321bf61af675fea9e5f14e2bd9d78be5d892a3b4f755212ce25f3701244` | `27.124.12.148:4452`、`:4453` | `candidate` | direct-routeで自動 | 一意なreversed vvaS設定構造と有効PE内配置 | 終端componentへの完全lineageとsocket利用data-flow |
| `72e8545f82529955a7189bb0131c25146de31bc9b7bdb75dd956365ebffa3400` | `170.62.130.47:449`、`:443` | `candidate` | nested PEを通常`extract()`へ渡すと自動 | Vulkan export → `_beginthreadex` → builder、二重Base64 host、primary重複＋alternateの3 slot、config serializer、3段前処理、RWX buffer、同一buffer間接call、protection restore | outer archiveからnested PEまでの標準direct-route再帰、完成terminal parserからWS2までの直接data-flow |
| `1692679c9f4e665f2570c0f7c9479288ae146755047b119388b07e74a20923fe` | `170.62.130.47:449`、`:443` | `candidate` | 追加静的解析では復元、現行自動parserは未完 | CEF alias export → local CRT wrapper → `CreateThread` → callback producer、二重Base64 3 slot、config serializer、3段前処理、RWX buffer、同一buffer間接call、protection restore | 2,001-byte config gapの完全生成、現行producer parser後段、terminal socket proof |

`72e854...`と`169267...`は同じC2値へ収束しますが、別検体であるためcase単位の候補として保持します。`169267...`は値の復元には成功したものの、同じ検体を現在の通常CLIへ投入するだけではendpointを出力できないため、自動成功件数へ含めません。

`2de286...`では`134.122.130.202:8080`／`:8888`とloader／stage URLに相当するnetwork literalを観測しましたが、設定consumerへ結べなかったため、C2設定復元件数から除外しました。

## 公開exact-SHA照合

100 SHA-256すべてを公開情報で完全一致検索しました。調査時点で、exact SHA-256に対応する公開reportは26件、familyとC2を報告するものは11件、placeholderと重複を除くC2 endpointは15個でした。74件の未発見は、公開検索indexと閲覧可能reportで見つからなかったという意味であり、report不存在の証明ではありません。

ローカルで復元した5件は、公開TriageまたはThreatFoxが同じexact SHA-256へ報告する値とも一致しました。ただし、外部sandbox表示や脅威情報だけではローカルcode lineage、protocol、livenessを確定できないため、証拠区分の昇格には使っていません。

## 追加した検出手法

1. **x64 vvaS終端proof**: R8 callback、R9 object、thread context、RIP-relative vtable、parser global、同一interface object、同一socket fieldを追跡します。
2. **modern reversed config**: `p1/o1/t1`から`ur`／`ps`までの完全field順序と型を検証し、直接C2とfallback resolverを分離します。
3. **`IpDate` compact route**: `i:<host>|p:<port>`とregistry markerをmapped非resource領域で相関します。
4. **`codecode` bootstrap route**: 固有request、PEB参照、XOR `0x2B`、3-slot設定を相関します。
5. **19文字鍵RC4 full config**: 完全grammarと一意な標準RC4復号だけを採用します。
6. **modified-RC4 3-record container**: record境界、変形PRGA、header-stomped AMD64 PE、固定長configを検証します。
7. **`Server.log` RC4 route**: 標準RC4後のPE32 DLL、`NtHandleCallback` export、reversed configを検証します。
8. **NSIS／XOR／ZipCrypto／RC4 sidecar route**: 同じNSIS parentの完全inventory、member SHA-256／size／CRC、codeから復元した変換を結合します。
9. **CA01 outer builder candidate route**: VulkanまたはCEF exportからthread backend、二重Base64 3-slot builder、memory-stage consumerまでを追跡します。

生鍵、暗号文、完全config、復元payloadは公開しません。終端socket proofがないrouteはfamilyと確定C2へ昇格しません。

## 誤検出抑制

- `D3D11`や`wevtapi`のimportだけで成立していたnative loader routeを削除しました。初回32件の`native_loader_candidate`は最終13件となり、C2復元は失っていません。
- generic 7-Zip SFX magicだけではYuanbao配布チェーンへ帰属しないようfail-closedにしました。
- resource、overlay、未参照plaintext、別functionのAPI union、複数の相反設定、未解決indirect flowは確定証拠にしません。
- loopback、private、link-local IPと予約domainはC2候補へ含めません。NSIS多段routeは各段の候補数、参照数、復号試行数、総変換byte数の上限に達した場合、途中までの成功を採用せずfail-closedにします。
- 外部signature、TCP open、HTTP応答、証明書は単独でfamilyまたはC2を確定しません。
- `493474...`はWindows Defender delta CAB／VDMに一致する非ValleyRAT候補であり、provider候補ラベルの誤差を示します。

## 自動解析上の残課題

- standard one-shot 100件は保守的な状態判定ではすべて`partial`でした。解析処理の失敗ではなく、代表関数や終端payloadまで証拠が閉じなかったことを表します。
- direct-routeの最終variantは、`vvas_reversed_config_terminal` 1件、`vvas_reversed_config_pe_candidate` 1件、`dll_sideload_vvas_bundle` 1件、`native_export_funnel_resource_network_route` 14件、`native_loader_candidate` 13件、`silverfox_style_infection_loader` 10件、`unresolved_variant` 60件です。
- archive／ISO／NSISを経由する検体は、top-level bytesだけのdirect-routeでは内側componentへ届きません。親子identityが検証済みの場合だけnested PEを再投入するcollection-level adapterが必要です。
- `169267...`のCEF型はwrapper lineageまでは汎用化できましたが、producer parser後段を安全に一般化する作業が残ります。
- 19文字RC4、modified RC4、`Server.log`、modern AES/HMACはrouteを実装しましたが、この固定100件で新たな陽性はありませんでした。異なる時期・campaignのholdoutが必要です。

## 実装検証

- 今回変更したValleyRAT抽出routeの対象回帰テスト182件、NSIS多段pipeline adapter 4件、automatic handler preflight 2件、対象別datastore staging helper 43件が成功しました。
- Ruff、Python構文検証、`git diff --check`が成功しました。
- 01c204の実データを最終安全上限の追加後に再解析し、NSIS → XOR → ZipCrypto → RC4 → vvaS終端の3段lineage、終端SHA-256、endpoint件数が変更前と同一であることを確認しました。

## 安全境界と保管

- 検体、復元payload、shellcodeを実行していません。
- C2、fallback resolver、dead-drop、検体内URLへ接続していません。
- 検体取得ではMalwareBazaar Community APIを使用し、技術照合では公開OSINTと公開sandbox reportだけを参照しました。
- raw config、復号鍵、暗号文、payload、private pathを公開成果物へ含めていません。
- 非公開検体とone-shot成果物は検体単位のpassword付きAES-256 ZIPへ分離し、指定S3 bucketで100件すべてのobject size、SSE `AES256`、archive SHA-256 metadataを検証済みです。追加深掘り3件も解析対象別に分離して同じ検証を完了しました。upload receiptはリポジトリへ含めません。
- 重複して生成された2 caseは、意味的内容、成果物数、安全flag、全file SHA-256を監査し、完全な側を最終100件へ採用しました。

## 参照した公開技術情報

- [ADAMnetworks: ValleyRAT signed profiler and 19-byte text file](https://adamnet.works/blog/valleyrat-signed-profiler-and-19-byte-text-file/) — modern reversed config、`ur` fallback、`ps` session material、nonce／AES-CBC record
- [OIS: Silver Fox Part 3 — DLL Sideloading ValleyRAT](https://oisthreat.com/en/research/silverfox-part3-dll-sideloading-valleyrat/) — `Server.log` RC4 route、14-byte header、UDP／ARQ
- [Fortinet: Threat Campaign Spreads Winos4.0 Through Game Application](https://www.fortinet.com/blog/threat-research/threat-campaign-spreads-winos4-through-game-application) — `codecode` bootstrap route
- [Proofpoint: TA4922 Suspected Chinese Crime Group Going Global](https://www.proofpoint.com/us/blog/threat-insight/ta4922-suspected-chinese-crime-group-going-global) — 19文字RC4 config
- [Forcepoint: ValleyRAT Overwolf Sideload Tax Scam](https://www.forcepoint.com/blog/x-labs/valleyrat-overwolf-sideload-tax-scam) — modified-RC4 3-record container
- [Splunk: ValleyRAT Insights, Tactics, Techniques, and Detection Methods](https://www.splunk.com/en_us/blog/security/valleyrat-insights-tactics-techniques-and-detection-methods.html) — `IpDate` compact config
