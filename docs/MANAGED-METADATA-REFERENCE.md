# 有界なmanaged metadata参照解析

`unpackers/managed_metadata.py`は、`dnfile`がparseしたCLR metadataの宣言を
上限内で照合する共通処理です。`managed_il_triage.py`と
`managed_proxy_deobfuscator.py`が同じ参照検証を使用します。検体、CLR、CILを
load・実行・emulationせず、通信や検体byteの保存を行いません。

## 解決する参照

- `MethodDef`と`Field`は、table種別、ゼロでないRID、実在する行、signatureの
  境界と構造を確認します。
- `MemberRef`はfield signatureとmethod signatureを区別し、宣言元の
  coded indexが同じPEのmetadata表へ属し、行が実在することを確認します。
- `MethodSpec`は同じPEの`MethodDefOrRef`へ解決します。generic引数の宣言数、
  対象methodのgeneric parameter数との一致、各型signature、終端を確認します。
  復号や型の実行時生成は行いません。
- `calli`は`StandAloneSig`を検証しても、実行時のcalleeを確定できないため
  `indirect_call_target_not_statically_known`を維持します。
- 範囲外RID、未知table、破損signature、fieldを指すmethod参照、不正な
  coded indexは、tokenと固定理由を持つ`unresolved`として保持します。
  parser例外の本文や秘密値は結果へ転記しません。

signatureは単体16,384 byte、要素1,024個、再帰32段を上限とします。
参照表はhard上限として1表20,000行、合計80,000行です。APIでは上限の
引下げだけを許可します。tableごとの存在状態、宣言行数の型・符号・有無、保持数、
宣言行数との不一致、打切り、欠落行、parser errorを`coverage()`へ残します。
表自体の欠落を正常な空表と混同せず、表の上限で保持しなかった行と、
上限以内なのに欠落した行を区別します。parser例外名もASCII識別子64文字以内へ
限定し、不適合な名前を`MetadataParseError`へ置き換えます。

## CILトリアージの出力

`static_references`は、集計対象の命令列上にある`call`、`callvirt`、`newobj`、
`calli`、`ldftn`、`ldvirtftn`、field load／storeの参照を保持します。
caller token、opcode、code-relative offset、target解決結果を記録します。
この関係は字句的参照であり、到達可能な実行path、branchの成立、例外経路、
virtual dispatchの実行時calleeを証明しません。

保持する参照のhard上限は20,000件です。既存CLIの`--max-references`では
既定値からの引下げだけを許可します。
`reference_coverage`は集計対象命令内の参照総数、保持数、省略数、保持済みの
未解決数を分離します。body破損やmetadata／命令／参照の上限到達がある場合、
`body_scan_complete`は`false`です。`runtime_targets_complete`は常に`false`です。

生token対応表はprivateな専用トリアージ結果だけで扱います。
再帰的な公開unpack summaryは`static_references`を除外し、件数と解析範囲を
保持します。生signature、generic型名、resource内容を公開しません。

## proxy表の候補検証

既知word変換の適用前に、候補表を16,384 record／131,072 byteへ制限します。
ゼロRIDと同じfieldへの重複mappingを拒否し、95%の形式一致率だけで不正recordを
含む表全体を採用しません。

PE全体を解析する入口では、全recordのfieldとtargetをmetadata宣言へ照合します。
一部のtokenが存在しない、field signatureをmethodとして使っている、MethodSpecが
破損している場合は候補全体を拒否します。拒否した候補はresource SHA-256、
変換profile、record数、固定理由ごとの件数を`rejected_candidates`へ残します。
token対応表を公開するものではありません。

resourceだけを渡す低水準APIはmetadataを持たないため、結果を
`syntactic_candidate_only`として区別します。metadata照合後も
`metadata_declaration_validated_candidate`に留め、実行時dispatch、protector帰属、
仮想化解除、終端payload取得、family確定、C2確認へ昇格しません。

## 制約と次の改善対象

この共通処理はPE／CLR全体の完全な構造validatorではありません。
generic制約、型のassignability、TypeSpecの実行時意味、framework AssemblyRefの
真正性、override／delegate target、field producerのreaching definitionを
証明しません。下記のhelperは限定ASCII関連APIの参照宣言を追加照合しますが、
実行時assemblyの真正性を暗号学的に検証するものではありません。

resourceの取得callと具体的resourceを結ぶdataflow、支配関係、constant producer、
復号chainの検証は別工程です。参照列の取得だけで過去の未解決caseを完了へ
更新してはいけません。今回の回帰試験は実検体の復元成功率や誤検知率を測りません。

## framework参照宣言の限定照合

`MetadataResolver.match_framework_member(token, profile_id)`は、汎用の
`resolve()`を変更せず、レビュー済みの参照宣言だけを追加照合するAPIです。
先行profileは次の2件です。

- `system_text_encoding_get_ascii_v1`: `System.Text.Encoding::get_ASCII()`の
  static・非generic宣言で、戻値が同じassembly identityの`Encoding`であることを
  確認します。
- `system_text_encoding_get_bytes_string_v1`: `System.Text.Encoding`または
  `System.Text.ASCIIEncoding`の`GetBytes(string)`について、instance・非generic、
  `byte[]`戻値、引数1個を確認します。byte arrayや追加引数を持つ別overload、
  byref、vararg、未知modifierを受理しません。

MemberRefのownerは、同じPEのTypeRefからAssemblyRefへ解決します。
namespace／type／member名、default calling convention、has-this、generic数、
戻値とすべての引数を照合します。class戻値のTypeRefもownerと同じassembly
identityへ結び付けます。TypeDef、TypeSpec、同名の検体内MethodDef、未知scope、
scope cycle、8段を超えるTypeRef chainは受理しません。

初期対応は`mscorlib`とpublic key token `b77a5c561934e089`のexact pairだけです。
versionは`2.0.0.0`と`4.0.0.0`、cultureはneutral、AssemblyRefのraw flagsは0に
限定します。assembly名集合とtoken集合の直積では判定しません。
full public key、retargetable、architecture／JIT flag、別runtime／version／tokenは
未レビューとして拒否します。追加する場合は独立したprofileと合成回帰が必要です。

成功状態は`matched_declaration`です。結果はprofile、API識別子、signature
SHA-256、レビュー済みversionと固定診断だけを持ち、生のowner／member名や
signatureを含みません。汎用解決後にsignatureが変化した場合も拒否します。
以下は成功時も`false`であり、成功状態だけから推論してはいけません。

- `runtime_assembly_integrity_verified`: 実行時にロードされるassemblyの真正性
- `runtime_dispatch_verified`: virtual dispatchの実際の呼出し先
- `receiver_dataflow_verified`: instance receiverのproducerと使用の結び付き
- `side_effect_free_verified`: 副作用がないこと
- `nonthrowing_verified`: 例外が発生しないこと

とくに`GetBytes(string)`の宣言が一致しても、receiverがASCII encodingである
証明にはなりません。利用側は`get_ASCII`の戻値と同一receiverの使用、stringの
literal provenance、正常CFGでの定義・使用、別のwriteやaliasがないことを確認する
必要があります。helperは検体methodの評価、純粋性の推測、CLR呼出しを行いません。

`Environment.GetFolderPath`は環境依存なので、この先行profileには含めません。
このAPIを具体的なhost pathや空文字へ変換して設定抽出を完了させてはいけません。
未解決producerと、それに依存しない設定fieldの回収範囲を別々に扱う必要があります。

## 検証

全fixtureは無害な合成metadata・非実行命令objectです。正常なMethodSpec、fieldと
methodの区別、破損signature、偽RID、別table object、欠落行、上限、未知token、
proxy表の一部不正・重複、秘密値を含むparser例外を確認します。framework照合では
正常なgetterと2種類のowner、assembly/tokenの不正な組、version／culture／flags、
同名の検体内method、全signatureの差分、戻値型のscope、cycle、件数・深さ上限を
確認します。実検体やCLRをロードする試験ではありません。

```powershell
python -B -m pytest unpackers/tests/test_managed_metadata.py `
  unpackers/tests/test_managed_il_triage.py `
  unpackers/tests/test_managed_proxy_deobfuscator.py `
  unpackers/tests/test_large_file_bounds.py -q
```
