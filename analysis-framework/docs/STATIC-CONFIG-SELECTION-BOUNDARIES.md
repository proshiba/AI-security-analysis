# 静的設定選択の完全性と相反拒否

この文書は2026年9月28日に通常ソースへ反映した設定選択の追加境界を説明します。AI、検体実行、C2・dead-dropへの接続に依存しません。未知検体の抽出成功率や、実行時に使われる設定の証明ではありません。

## 共通原則

完全な候補を一つ発見しても、認識済みの相反候補や探索打切りを捨てて成功へ戻しません。理由は固定した識別子で記録し、失敗診断へ鍵・raw設定・URL・例外本文を付加しません。各方式の既存予算は増量せず、候補と確定C2、outerと独立した終端層の証拠を分けます。

| 対象 | 拒否・未完了の条件 | 維持する正常契約 |
|---|---|---|
| PureRAT managed nested message | 深さ3の先に構造messageが残る、unique parse試行が128件を超える | 深さ0～3の対応message、浅い位置で評価済みrawの重複排除、最大4MiB・4096fields・64encoded候補 |
| PureRAT managed host | 旧host／port条件を満たすmessageのhost field1が複数 | 単一hostとpacked／unpacked port。wrapperを設定と推測しない |
| StealC v1 | 同keyの復号列、または既存final 4keys内に異なる完全設定 | 全7field identity、同値の先頭表記、公開RC4／XORの未回復`None` |
| Vidar repeated XOR | 認識済み設定のfield切断、明示0長URL終端が無い、32recordの先が非0長 | `None`と正当な空fieldの区別、最大32recordと64候補試行、公開未回復の空dict |
| ValleyRAT native lineage | 深さ4に未証明の構造loader／KBND footer候補が残る、追加cap probeが例外になる | strict終端proofをcap前に評価、32visited、cycle／duplicate、子bytesのidentity照合 |

## PureRATのnested探索

解析の成功・失敗を問わず、重複排除後のunique parse試行を128件枠へ一度課金します。129番目のparserは呼びません。深さ4の構造確認が成功したら、正規化・yield・設定選択の前に固定理由で拒否します。構造ではないplaintext leafのparse失敗は従来どおり無視します。

これはschemaを持たない構造probeです。例えば`192.0.2.1`の9bytesは偶然fixed64 protobufとしても成立するため、深さ3にあるその設定は保守的に拒否されます。深さ0～2の同じIPv4設定は維持します。深さ3の全plaintext互換を保証しません。

128件は各decoded clear messageの枠であり、64encoded候補を横断する新しい総CPU予算ではありません。非CHRDの同じmanaged入力は不完全設定から成功へ戻しませんが、CHRDの独立した終端bytesの厳密再抽出を一律禁止する変更ではありません。outer／terminal全体の一意性は別の証明が必要です。

現在のmanaged出力はhostを一つだけ返すため、複数field1から先頭だけを選ぶことを禁止します。同値duplicateも未レビューmultiplicityとして保守的に拒否します。旧first-host／port条件を満たすmessageだけを固定理由でdecoder全体から拒否し、他のsingle-host候補だけが残って成功へ戻る退行を防ぎます。field番号の存在だけで任意wrapperを設定と扱いません。実schemaのsingular／repeated／last-winsを証明した変更ではありません。

## StealCの相反と公開互換

最初のHTTP(S)配置が既存のgate／DLL／任意build schemaを満たす場合だけ、同じ復号列の後続完全配置を同じ条件で比較します。最初の配置が不完全なら従来の未回復であり、後方配置による救済はしません。後続不完全配置も完全候補へ昇格しません。

内部のstrict復元は既知相反を固定例外で区別します。公開`extract_rc4_profile`／`extract_xor_profile`は相反時も従来の`None`を返しますが、通常`extract`は内部strict入口を使い、既知相反後に別key・XOR・protected wrapperへfallbackしません。統合adapterも`profile_selection_error=conflicting_profiles`の場合だけ元の未解決結果を返し、v2／endpoint候補で再確定しません。

512keys、4096encoded値、単体encoded長4096、probe64、final keys4は不変です。全入力・全key・他方式で相反が存在しない証明ではありません。日本語limitationsと、成功時に未回復説明を除くprefixも連動させています。

## Vidarのrecord終端と全view選択

versionと最初のHTTP／ASCII URLで認識できた設定について、field長byte欠如、復号範囲外、URL終端未確認を不完全として返します。`_try_config_assessment`のtupleで通常grammar不一致と不完全を分離し、既存`_try_config`のdict／`None`契約は維持します。

32件の非空recordに達したら、次recordのURL length byteを1byteだけ確認します。0なら明示終端、欠如または非0なら不完全であり、33件目のpayloadは復号しません。不完全候補を一つでも認識したviewは、他の完全候補を保持していても選択せず、`reason=incomplete_record_profile`、`status=not_recovered`、`scan_complete=False`になります。

候補の最小sizeは693から371bytesへ縮め、最初のtag／agentが切断された形も認識します。64候補試行と64MiB view上限は維持します。既存の非ASCII build／tag／agentなど、通常grammar不一致を新たな設定証拠にはしません。

このschemaには独立blobの外部lengthがありません。後続blobが欠如fieldを物理的に補ったunframed viewについて、元の切断を常に識別できる保証はありません。境界を推測してbytesを切り離しません。設定回収の成功も、dead-dropから最終C2を取得した証明ではなく、既存URL役割と`final_c2_recovered=False`を維持します。

## ValleyRATの深さ打切り

strict terminal proofを深さ上限より先に評価するため、深さ4で証明済みの終端は受理します。未証明nodeではcap時のcontext／構造predicateだけを確認し、認識済みloaderなら全体confirmedを拒否します。capで追加復号stageや子nodeは生成しません。

対応するKBNDのAPI群が構造clusterへ必ず包含されないため、既存loaderの判断にも使う`KBND` footerをcap-onlyの保守的候補signalに含めます。contextが取得できない場合も未完了へ閉じます。footerだけではstage、family、C2を証明せず、偶然や破損したfooterも保守的partialとなり得ます。footer無しの未知leafは従来扱いを維持します。

固定理由`native_loader_lineage_depth_limit_exhausted`を記録し、追加cap probeの例外では`native_loader_lineage_depth_context_probe_failed`も記録します。不完全なproducerはstrict-child consumerへ終端として渡さず、復元子集合もcompleteとして返しません。

capでPE metadata／resource／条件付き静的命令parseが一度増えることがあります。visited32・function8192・instruction250000などの既存枠を使いますが、terminal probeとcontextとconsumerを横断する新しいparser CPU総予算ではありません。既存parserが`None`へ戻す未知形を全branch完全性の証明と混同しません。

## 検証と残件

追加の人工fixtureは通常moduleを直接importし、私有conftest・絶対path・固定source SHAへ依存しません。採用前の候補検証、独立source-onlyレビュー、通常moduleでの回帰、全handler起動前検証は別の証拠です。最終結果は[改善概要](STATIC-AUTOMATION-IMPROVEMENTS-20260927.md)に整理します。

PureRATのmetadata走査予算の失敗とraw文字列fallbackの証拠境界、未知loader形式、未探索key／profile、全入力の共有CPU予算は残る検証課題です。これらを今回の修正で完了したとは記録しません。

現在のPureRATは、`#US`のheap破損と16,384文字列超過を同じ`_ManagedMetadataError`で扱い、収集中の文字列を破棄した後、raw fallbackが設定を返せると保存したエラーを結果へ残しません。そのfallbackは入力全体の連続ASCII／UTF-16LE文字列走査であり、ManifestResourceの範囲・来歴を独立検証するreaderではありません。下流の設定復元flagにもmetadata不完全性が伝わらないため、今回のdepth／host修正を、入力全体の候補列挙完全性の保証とは扱えません。

次の修正では、破損と予算打切りの理由、上限前の候補、未走査部分の相反、raw fallback自身の上限を別々に検証する必要があります。独立resourceから厳密に復元できたという証拠をraw走査の成功で代用しません。CHRDの別terminal bytesは別来歴scopeとして扱い、outerの不完全性だけから一律に許可・拒否を決めません。
