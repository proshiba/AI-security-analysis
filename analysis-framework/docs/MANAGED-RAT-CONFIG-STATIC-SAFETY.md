# managed RAT設定回収の構文限定解析と安全境界

`common/dotnet_rat_config.py`はAsyncRAT、VenomRAT、DCRatのレビュー済み設定形式を静的に回収します。Settingsという型名、暗号の認証成功、設定endpointの取得だけではファミリーや稼働中C2を確定しません。各統合handlerの独立した構造・protocol証拠と既存品質ゲートが引き続き必要です。

## 初期化literalとfield参照

一意なSettings `.cctor`の隣接する`ldstr`→`stsfld`を回収します。同じ初期化method内で先に確定したstatic string fieldに限り、隣接`ldsfld`→`stsfld`の参照を解決できます。間にある`nop`は許容します。

cctor宣言はdefault calling convention、引数なし、戻り値`void`の完全signatureと`mdStatic=true`を共有setupで検証します。インスタンスmethod、引数あり、別戻り値、破損signatureを初期化methodとして採用しません。宣言一致だけでruntime assemblyや実行時経路を証明しません。

raw `Flags`／`ImplFlags`は非boolのuint16を要求します。static bit不足、Abstract、PInvoke、未レビューのUnmanagedExport、不正なaccess mask、IL managed以外のcode種別、ForwardRef、InternalCallは拒否します。`ImplFlags`の未レビュー／reserved bitも拒否し、未知flagを無害と推測しません。NoInlining、Synchronized、NoOptimization、PreserveSig、AggressiveInlining／AggressiveOptimizationの既知bitは許容します。SpecialName／RTSpecialNameは本単位では必須化せず、いずれのflagもruntime真正性の証明へ転用しません。

これは命令の構文対応付けであり、stack、CLR、CIL、CPU、VM、検体由来の関数を実行・エミュレーションするものではありません。前方参照、別型への参照・代入、未解決alias、重複代入、重複field名、不正token、static string以外のfield、複数cctor、分岐、例外handler、`ret`後の命令は拒否します。未知のcallやfield addressのescapeがあるSettings初期化も、副作用を推測せず拒否します。変換関数や任意演算を評価するfallbackはありません。

## 診断専用のfield単位assessment

`assess_settings_literals(data, settings_type)`は、従来の`settings_literals`成功契約と分離した評価APIです。`SettingsLiteralAssessment`の候補値は非公開属性にのみ保持し、`settings_literal_diagnostics(assessment)`で公開可能な診断copyを取得します。通常の`recover`とfamily handlerはassessment候補を使用しません。

状態は次の3つです。

- `complete`: 従来のstrict構文契約が成立し、観測した代入に無効化理由や未解決効果がありません。ファミリーや稼働中C2の確定を意味しません。
- `partial`: 有効なmetadataとbodyからliteral代入構文を観測しましたが、strict契約の全体成立を示せません。候補を通常の成功map、復号済み設定、確定C2として扱ってはいけません。
- `rejected`: metadata、body／instruction境界、参照token、signature、または上限が不正・不完全です。診断のfield一覧と非公開候補を空にし、途中の観測をpartial成功として残しません。

field診断にはFieldDef token、代入offset、隣接producerのoffset、依存FieldDef token、固定reasonだけを含めます。field名、literal値、生signature、call名、例外本文は含めません。`repr`、文字列化、公開state projectionにも値やfield名を含めず、標準JSONでassessment本体を直接serializeすることはできません。非公開属性を意図的にserialize・公開するconsumerはこの契約の対象外です。

literalは隣接`ldstr`→`stsfld`、copyは同cctorの先行した同型fieldの隣接`ldsfld`→`stsfld`だけを観測します。`nop`以外の介在命令を変換・評価せず、複数の連続producer、同field再代入、同名field、前方参照、別型依存、未証明の右辺をfield単位で無効化します。無効化したfieldへの構文依存は推移的に無効化します。これは到達性・stack・値の計算ではありません。

未知call、`newobj`、関数address、`calli`、address escape、間接書込み、別型の静的アクセスは、method全体の`effects_unresolved=true`を残します。metadata上のcall宣言が解決できても、副作用なし・例外なし・実行時dispatchの証明にはしません。`Environment.GetFolderPath`などのAPI名だけでcallを無害化せず、pathやcall結果を具体化しません。

分岐はtargetがinstruction境界内にあること、EHは領域境界とcatch tokenを検証するだけです。CFG、分岐条件、handler経路は解釈しません。分岐・EH・未証明の終了位置があるfieldは`observed_literal`であり、最終実行時値の証拠ではありません。method効果が解決している場合でも、field局所のinvalid化によって全体が`partial`になることがあります。この場合、影響を受けないfieldの`proven_literal`は構文契約内の代入を意味するだけで、通常recoverへ渡す許可ではありません。

field、全代入、未解決効果はそれぞれ4,096件以下です。UserStringはcctor内tokenごとに1回だけ取得し、immutable文字列参照をcopy先でも共有します。strictとassessmentは同じreaderを使い、distinct literal 4,096件、UTF-8合計保持量32 MiB以下に限定します。UTF-8サイズは8,192文字ずつ数え、日本語の複数字節も保持予算へ含めます。予算超過のliteralはcacheへ入れず、assessmentの途中候補も破棄します。

既存の入力32 MiB、metadata各20,000行、body 1 MiB、65,536命令上限も維持します。診断の上限到達は`rejected`とし、黙った打切りや候補の成功昇格はしません。公開診断をCLIや公開caseへ接続する処理は本単位では追加していません。

## ASCII saltの限定宣言とreceiver構文

`static_salt`は`nop`を除いたcctor全体が`call(get_ASCII)`→`ldstr`→`callvirt(GetBytes(string))`→`stsfld(Salt)`→`ret`である場合だけを対象にします。literalの逆順、余剰producer、receiver置換、local alias、別call、再代入、分岐/EHは拒否します。salt fieldは同型・同名一意の非literal static `byte[]`宣言に限ります。

共有`MetadataResolver.match_framework_member`の2つの固定profileを使い、MemberRefのowner、member名、全signature、assembly名とpublic key tokenの組、対応version、neutral culture、flagsを照合します。getterとGetBytes双方のowner profileは`system_text_encoding`で一致し、assembly identity profileとversionも完全一致しなければなりません。個別に対応した`ASCIIEncoding.GetBytes`や、異なるmscorlib versionの組合せは隣接receiverの根拠にしません。sample内の同名MethodDefや偽framework宣言は受理しません。

これはレビュー済みmetadataと隣接構文の一致に基づく、限定ASCII形式のオフライン回収です。runtime assemblyの真正性、dispatch、副作用なし、nonthrowingを証明せず、呼出しやCILを実行・エミュレーションしません。salt宣言一致だけで認証設定、ファミリー、稼働C2を確定することはなく、その後のHMACと独立した構造・protocol確認を代替しません。

## 認証設定の検証

- 入力は32 MiB、必要metadata tableは各20,000行、初期化methodは65,536命令以下です。CIL本体の既存1 MiB上限も維持します。
- 暗号化設定blobは16 MiB以下、master keyはUTF-8で4,096 byte以下です。暗号化blobの形式・サイズを確認し、HMAC-SHA256の完全一致後にAES-CBC/PKCS7を復号します。
- 1設定回収につきPBKDF2を1回だけ実施し、同じ派生鍵を全必須fieldへ使います。必須fieldの欠落、型不一致、不正UTF-8、認証失敗は成功へ変換しません。
- hostとportは全値を検証します。混在する不正portを捨てる、空endpointを成功とする、64件を超えるhost×portの直積を公開することはありません。
- version、group、boolean、証明書も検証します。証明書のhashとsizeは設定由来の静的証拠であり、証明書不一致だけで非C2とは判断しません。
- `dynamic_config_url`はoriginのみを公開し、`dynamic_config_url_scope=origin_only`を付けます。userinfo、path、query、fragmentは秘密を含み得るため保持しません。この値を後段取得用の完全URLとして使ってはいけません。

## 共通profileの走査と省略状態

`extractors/profiled_family.py`では1literalを8,192文字以下に限定します。長いrunを切り分けて人工的なmarkerやendpointを作らず、run全体を除外します。文字列件数、所見件数、決定的な3-window走査の上限は維持します。

`config.scan_diagnostics`に保持文字列数、長大runの件数、文字列上限到達、所見省略数、`scan_complete`を記録します。未検出は設定や通信能力が存在しない証拠ではありません。走査が全入力を対象にしていても、文字列や所見の上限に達した場合は`scan_complete=false`です。

bare endpointにもURLと同じ役割を適用します。既知の証明書・文書・vendor値を除外し、公開IP探索serviceは`host_discovery_service`、共有配布hostは`stage_url_candidate`とします。復号済み設定ではないliteralは`candidate`のままです。

## 合成テスト

リポジトリrootから次を実行します。

```powershell
python -B -m pytest -q analysis-framework/tests/test_dotnet_rat_config.py analysis-framework/tests/test_dotnet_rat_config_safety.py extractors/tests/test_profiled_family.py extractors/tests/test_profiled_family_scan_limits.py
```

テストは合成metadata、命令record、暗号化文字列だけを使います。正常な直線代入、未知callのあるpartial、分岐/EHの観測、再代入と依存無効化、公開projectionの秘匿、破損token・signature・body、上限拒否を検証します。実検体、復元payload、CIL、CLR、VM、スクリプトは実行せず、networkへ接続しません。合成fixtureの成功率は実検体の抽出成功率や誤検知率を示しません。

## 未対応と次の改善

分岐を含む初期化の最終値、任意のstring変換、他型の静的初期化順、保護された設定は未対応として残します。salt初期化はframework参照宣言を照合しても、runtime assemblyの真正性までを立証していません。暗号化形式の認証成功とprotocolの独立確認を代替する根拠には使いません。公開失敗診断の例外型だけから個別検体の内部失敗原因を断定せず、新たな構文や形式は別のレビュー済みprofileと合成陰性・破損・上限テストへ戻します。
