# CLRリソース宣言の入力照合と共有予算

## 目的

`managed_il_triage.py`と`managed_proxy_deobfuscator.py`は、リソース名・長さ・位置をparserの表示だけから信用せず、同じ入力bytesにあるPE、CLI、metadata、`ManifestResource`の宣言と照合します。共通処理は`unpackers/managed_resources.py`、`dnfile_resource_adapter.py`、`clr_input_binding.py`、`managed_resource_snapshot.py`です。

この仕組みは静的な記述子の取得と検証です。リソース本文をCLRでロードせず、外部のlinked resourceを取得せず、native／CIL命令を実行・emulationしません。記述子を得ただけでは、復号・終端payload・family・C2を確認したことになりません。

## 入力に結び付ける範囲

通常consumerでは次を照合します。

1. immutableなexact `bytes`、PE header、CLI directory、sectionの一意なfile-backed範囲。
2. metadata root、宣言されたstream、table layoutとrow count、同じ入力内の`#Strings`。
3. `ManifestResource`のOffset、Name index、Implementation coded index。
4. embedded resourceの4-byte長さと本文範囲、記述子相互の重複と名前の曖昧性。
5. 同じparser・table・row container・row・heapに由来する共有snapshotの再消費時の一致。

`File`または`AssemblyRef`へ結び付いたlinked resourceはembedded本文として扱いません。RIDと同一tableの関係だけを確認し、本文を外部へ要求しません。

parserが最初に現れたRVA mappingだけを返す場合も、それを単独の証明にはしません。部分的なsection交差、raw領域の別名、CLI宣言とparser viewの差、宣言されていないstreamのlookalikeは拒否対象です。

## 共有する予算

| 予算 | 固定上限 | 保証する範囲 |
|---|---:|---|
| 単一入力 | 512 MiB | helperの入力受付 |
| 対象metadata table | 1 tableあたり20,000行、合計80,000行 | 固定13 tableのrow予約 |
| `ManifestResource` | 4,096行 | 記述子の列挙 |
| resource本文 | 個別・合計64 MiB | 検証して消費する本文範囲 |
| section | 96個 | file-backed mapping検証 |
| resource名 | 512文字 | 内部で保持する名前 |
| `#Strings` | 16 MiB | 検証するheap |

固定13 tableは`TypeRef`、`TypeDef`、`Field`、`MethodDef`、`MemberRef`、`StandAloneSig`、`ModuleRef`、`TypeSpec`、`MethodSpec`、`AssemblyRef`、`File`、`ExportedType`、`ManifestResource`です。callerは上限を下げられますが、boolean・0・負値・固定上限を超える値は受理しません。

リソースの予約と`MetadataResolver`は同じsnapshotを使い、同じ行の追加予約を避けます。一方、再消費時にはidentityの再確認が必要です。`unique_rows_reserved`、`snapshot_row_visits_this_call`、`shared_snapshot_identity_visits`を分けて出力し、CPU作業がすべて省略されたとは説明しません。

通常triageが独自のmethod・reference予算を下げた場合、共有metadata予約が先に不足することがあります。その場合はmethod本文や一部参照だけを成功として返さず、metadataの未確定理由を先に返します。

## 不完全な結果の扱い

未知のcallback、未対応parser view、row count不一致、範囲不正、曖昧な名前、予算不足、snapshot差し替えがあれば、coverageは`partial`です。不完全な一覧の先頭だけを検証済み記述子として公開せず、全記述子を破棄します。

通常consumerは`input_binding_verified=true`を要求します。直接helperへ渡すordinaryなテストviewは、内部の構造比較用として`parser_view_only`を持ちます。viewだけの結果を通常入力の証明へ昇格させるfallbackはありません。

公開coverageとreprには固定reason・件数・予算・状態だけを含めます。名前、resource本文、raw offset、未知objectの文字列表現、parser例外本文は含めません。triageの別の既存出力には、検証後のresource名・size・hash・entropyが残るため、このcoverageの非公開境界を全出力の秘密値除去保証と混同しません。

## 起動前の依存監査

固定5helperはsource SHA-256だけで許可せず、全helperとclass methodの本文を監査します。reflection、固定factoryの`object.__new__(MetadataResolver)`は、固定class・import・receiver・呼出式・contextとcallee本文の条件に限定します。汎用reflectionや任意allocatorの許可ではありません。

通常2consumerのsource、`dnPE(data=data, clr_lazy_load=True)`起点、tuple要素、全caller、namespaceとreceiverの再代入も照合します。未知callerや旧互換wrapperはhandlerの安全入口になりません。同名関数・methodの重複は、source pinを更新しても拒否します。

triage／proxy全体には従来の起動前監査上の未対応呼出しが残ります。リソース依存の監査成功だけで、そのutility全体を新しい安全handlerとして登録する変更はありません。既存family handlerの別の入口と条件は維持します。

## 証明しないこと

- 固定2consumerには、全45tableの宣言を`dnfile.dnPE`前に制限する[構築前検査](MANAGED-CONSTRUCTOR-PREFLIGHT.md)を追加しました。ただしconstructor自体の全allocation・CPU作業を保証するものではなく、構築後の固定13table共有snapshotとも別の境界です。
- `TypeDef.MethodList`／`FieldList`など、別のconsumerによる暗黙の全table loaderを停止する保証はありません。人工nonempty fixtureでは、loader後もrow container identityを維持して再消費できることを確認しています。
- 全metadata高水準attribute、全signature、実行時dispatch、framework assemblyの真正性を独立raw投影で完全検証する仕組みではありません。
- `dnfile` 0.18.0の固定遅延読取り形状を対象とします。eager viewや未知実装を推測で互換扱いしません。
- Python側の任意objectやprocess全体に対する万能sandboxではありません。既存のsource監査、隔離worker、OS境界は別途必要です。

## 人工試験

通常配置のhelper・consumer・既存triage移行は363件、10.69秒で成功しました。旧metadata・再帰的レイヤー・proxy・unpackerなどの358件も9.03秒で成功しています。入力は定数から生成する人工PEと静的な命令recordだけで、実検体・OS binary・compiler・外部通信を使いません。

初回の起動前監査119件は固定sourceで118件成功・1件失敗でした。AsyncRATの既存preflightが、同一source内の全能力列挙を余分な依存edgeとして数えることで深さ上限へ到達しました。真のimport・別sourceへのcallee到達は引き続き加算し、新4helperの能力列挙と固定allocatorのclass選択にだけ余分な加算を除く修正をしました。深さ上限12、file数上限96、cache確認前の深さ検査、全callee本文監査は維持しています。

修正後の監査127件と深さ陰性13件は140件すべて成功、902.87秒でした。開始前・終了後の通常source snapshotは一致しています。ValleyRATの既存fail-closed試験28件も196.02秒で成功しました。これらの結果だけで全handlerのruntime importや実検体への適用成功を確認したとは扱いません。

これらの試験数は実検体の解析成功率やC2抽出率ではありません。過去の未完了検体を成功へ書き換える処理も含みません。
