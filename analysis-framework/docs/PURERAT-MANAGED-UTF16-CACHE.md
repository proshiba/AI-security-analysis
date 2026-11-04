# PureRAT managed UTF-16 cacheの静的復元境界

## 目的

OMLXで復元したmanaged childの一部は、設定文字列を`#US`や平文resourceへ
保持しません。検証したbuildでは、32-byte keyと16-byte maskをCIL上で
複数回上書きし、maskを反転してkey先頭へXORした後、Eazfuscator系の
keyed-word transformでmanifest resourceを復元します。復元後の文字列は
`int32le byte_length | UTF-16LE bytes`として参照されます。

`unpackers/managed_purerat_cache_frontend.py`はreal CILからrecipeを一意に束縛し、
`unpackers/managed_purerat_cache.py`は証明済みrecipeを再生する後段を提供します。
検体、CLR、CIL、復元文字列を実行せず、外部通信もしません。

front-endは、cache accessor、exact resource名、internal decoder、検証済み
keyed-word transformをmetadataとcall関係で結びます。難読化dispatcherは
`stloc`、`ldloc`、`switch`の3入口をCLR stack効果どおりに区別し、決定済みの
単一路だけを解釈します。未知opcode、未知call、未定義static field、候補の複数成立、
状態・命令・時間上限への到達は、raw値を含まない安定した理由で拒否します。

## 必須の上流証拠

後段へ渡す前に、次の全項目をCILとmetadataから一意に束縛する必要があります。

- cache accessorが読むmanifest resource名
- key/mask配列のallocationと、決定済み単一路上のordered write列
- `Array.Reverse`後の16-byte maskを32-byte key先頭へXORするloop
- keyed-word transform methodと、そのmethod body hash、seed、addend
- 末尾1～3 byteを扱うpartial-word profile
- 個別cache値を後段schemaへ渡す場合は、そのcall-siteから得たexact offset集合

難読化名、metadata RIDの固定値、provider/protector labelはbuildをまたぐ根拠に
しません。分岐が未解決、resource名が重複、offsetが未知の場合は復元しません。

## ordered write

同じ配列indexへの複数回の上書きは、決定済みの単一路では通常のCIL semantics
です。そのため後段はfile順の「最初」や「最後」を推測せず、上流解析器が証明した
実行順のwrite列を再生します。全indexの最終値が具体化していない場合、または
index/valueが範囲外の場合はfail-closedで拒否します。

## UTF-16 cache

resource全体から「読めそうな文字列」やURLを走査しません。まずoffset 0からEOFまで
長さ付きtableとして完全に消費できることを検証します。個別値を後段schemaへ渡す場合は、
その完全tableのentry境界と一致する、上流で証明したexact offsetだけを選択します。
各entryについて次をすべて検証します。

- 4-byte signed lengthが非負、偶数、上限内
- 本文がresource境界内
- UTF-16LE strict decodeに成功
- 参照領域が相互に重ならない
- offset集合に重複がない

復元reportはresource/key/mask/文字列のhashと件数だけを返し、raw key、raw
resource、raw文字列、endpointを含めません。復元文字列は内部戻り値として既存の
厳格なPureRAT config schemaへ渡します。

## 判定境界

cache復元成功は、難読化されたmanaged string routeの証拠です。単独では次を
許可しません。

- PureRAT family確定
- C2確定
- endpointのlive確認
- provider/protector名による帰属

family/config/C2へ昇格するには、同じ復元layerで既存のprotobuf/PFX/versionなどの
family-bound schemaを満たし、相反候補がないことが必要です。cache後に別の内部
transformが残るbuildは、そのtransformを別途証明できるまで未確定のままにします。

`analyze_purerat_terminal_semantics()`は、terminal semantic相関が成立しcache methodが
一意な場合にfront-endを呼びます。公開する統合結果はrecipe名、検証済み条件、entry
件数、安定理由だけです。復元文字列、key、resource、offset、endpointは統合reportへ
渡しません。後続の`string,int` transformが未対応の場合は
`secondary_string_transform_not_recovered`を返し、family/C2確認を許可しません。

## 2026-10-30の6件診断

厳格評価で`managed_omlx_terminal_recovered`と集計された6 rootは、実際には
OMLX childへ到達したroute候補でした。6件ともCIL semanticでは設定初期化とTLS
transportが相関しましたが、既存の厳格なfamily/config/C2 schemaは成立していません。

代表buildでは、AES/FieldRVA型SmartAssembly recipeではなく、上記のordered
key/maskとcustom keyed-word transformが確認されました。復元したcacheにもさらに
内部transformが続くため、loose domain候補をC2へ昇格していません。この境界を
維持することが、見かけ上の成功率より優先されます。

実行・通信なしのprivate検証では、利用可能な3つの異なるOMLX child variantで
front-endが完全cacheを再構成しました。entry数は169、169、21で、large/smallの
両variantを同じ構造条件で処理しています。検体hash、metadata RID、token、resource
名は受理条件へ固定していません。

代表variantではcache参照後にresource-backedな`string,int` char transformが二段続く
ことまで静的に確認しています。ただし、その一般化にはresource-name復元、integer
proxy table、各transformのcall-site bindingをすべて一意に証明する必要があります。
現時点ではvariant横断の証明と既存terminal schema／PFX確認が完了していないため、
この経路を自動昇格へ使用しません。これは未確定のblockerであり、loose URL、既知prefix、
固定引数から推測して回避しません。
