# managed TripleDES／GZIP resource復元の宣言照合

`unpackers/managed_tripledes_gzip.py`は、literal resource、Base64の16／24-byte keyと8-byte IV、CBC／PKCS7、4-byte長さprefix付きGZIP、`Assembly.Load(byte[])`へつながる既存の限定レシピを静的に検証します。検体、CLR、CIL、CPU、VM、復元PEの実行やエミュレーション、外部通信は行いません。復元結果は独立した子解析へ渡す候補であり、ファミリー、稼働中C2、terminal到達の確認ではありません。

## 型別のclassic .NET identity

PE入口`recover_managed_tripledes_gzip`では、assembly名集合と公開鍵token集合の直積を許可しません。次のexact pairだけを扱います。

| AssemblyRef名 | 公開鍵token | 対応version | 使用する型 |
| --- | --- | --- | --- |
| `mscorlib` | `b77a5c561934e089` | `2.0.0.0`、`4.0.0.0` | レシピに必要な暗号、stream、reflection、変換、cleanup、`System.Byte`の限定型 |
| `System` | `b77a5c561934e089` | `2.0.0.0`、`4.0.0.0` | `System.IO.Compression.GZipStream`、`CompressionMode`のみ |

両pairともneutral culture、整数のraw flags `0`が必要です。full public key、PublicKey flag、retargetable、未レビューのarchitecture／JIT flag、未知version、culture、名前とtokenの取り違えは受理しません。`System.IO.Stream::CopyTo`は`4.0.0.0`だけに限定します。

TypeRefのscopeとMemberRefのownerは、同じPEのmetadata表に所属する有効RIDとして確認します。行objectの表示名だけでは解決しません。型ごとに上表の所属assemblyを限定し、owner名・member名・default呼出規約・has-this・generic数0・全引数・戻値を完全照合します。署名内のclassとvalue-typeも区別し、型名が一致していても別assemblyや別versionの戻値／引数は拒否します。戻値だけを同名の偽型へ置き換える場合も同様です。

## 上限と未対応

TypeRef、MemberRef、AssemblyRefはそれぞれ16,384行以下です。共通`MetadataResolver`の総80,000行上限と、他のsnapshot対象表の上限も維持します。宣言行数の型不正、負数、実際の行数との不一致、欠落表、parse不完全、各行数／総行数上限超過は`framework_metadata_*`の固定理由で拒否します。名前は512文字、API署名は1,024 byte、引数は16個、型構造は深さ3・64項目以内です。非canonical compressed integerも拒否します。

modern .NET、`System.Runtime`などのfacade、type forwarding、nested TypeRef scope、ModuleRef、TypeSpec、MethodSpec、未知overload、custom modifier、byref、generic APIはこのレシピでは未対応です。以前の広い名前・token集合では構文上受理され得たものも、レビュー済みidentityでない場合は`framework_api_declaration_not_reviewed`と理由件数を残して候補にしません。これは対応範囲の意図的な制約であり、実検体の抽出率改善や対象に暗号機能が存在しないことを意味しません。

既存の16／24-byte key、`TransformFinalBlock`、`CryptoStream`のread／copy、local定義・使用、正常CFG支配、resourceと復元PE境界の検証は維持します。例外flow、実行時assembly置換、dispatch、receiverの完全なruntime意味論、非throwing、副作用の不存在は引き続き確認していません。

## 診断と合成試験

`framework_declaration_validation`には固定profile名`classic_dotnet_tripledes_gzip_v1`、一致したMemberRef件数、未レビュー理由別件数を記録します。生のassembly名、member名、token map、署名、key／IV、resource名は追加公開しません。scopeは`reviewed_metadata_declarations_only`です。`runtime_assembly_integrity_verified`、`runtime_dispatch_verified`、`side_effect_free_verified`、`nonthrowing_verified`は成功時も`false`です。`metadata_complete=true`は有界snapshotの完全性だけを示し、すべての宣言が対応していることを示しません。

`recover_model`は既存の正規化済み命令recordとresourceを検証する低水準入口です。callerが与えた名前だけから実PEのassembly identityを確認する入口ではありません。

合成fixtureによる試験は次のとおりです。無害なPE境界と非実行のmetadata／CIL記録だけを使い、検体や復元payloadを実行しません。

```powershell
& 'C:\Users\Administrator\Tools\Python313\python.exe' -B -m pytest -q analysis-framework/tests/test_managed_tripledes_gzip.py unpackers/tests/test_managed_metadata.py
```

classic version2／4、既存両復号レシピ、16／24-byte keyに加え、fake pair、full key、culture、flags、未知version、forward／foreign scope、戻値identity、class／value-type違い、署名破損、各表と総行数上限を試験します。合成試験の成功率は実検体の抽出成功率や誤検知率ではありません。
