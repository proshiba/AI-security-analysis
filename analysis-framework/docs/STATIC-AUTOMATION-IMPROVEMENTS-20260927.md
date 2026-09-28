# AI非依存の静的解析改善と再解析の進め方

この文書は、2026年9月27日から28日未明に、機能単位ごとに固定して検証した改善を整理します。検体を実行しない既存の一括解析に適用される改善と、履歴から次の改修対象を選ぶ機能を区別します。特定検体の解析結果や、全検体への成功率保証ではありません。

## 通常の自動解析で変わること

| 対象 | 実装した改善 | 成功として扱わない状態 |
|---|---|---|
| 宣言型の静的byte変換 | 単一・複数profileで入力、設定、処理量、保持量、候補走査、時間の予算を共有。strict JSON検証と内容に結び付いたcacheを使用 | 上限到達、未知設定、壊れた構造、走査未完了はpartialまたは拒否 |
| PE・通常ZIP構造 | PEのfile-backed領域、ZIPのcentral/local header、descriptor、範囲重複を照合 | header一致だけでは本文の復号・CRC・終端payloadの確認にならない |
| Donut候補 | 上限付きheader-onlyの構造観測を追加 | Donut本文を実行・emulation・自動復号しない。構造候補は終端復元ではない |
| managed RAT設定 | Settingsの所有型、field、cctor、literal代入、salt宣言、HMAC、AES、必須設定と組合せを厳密に検証 | 一部literal、未対応制御フロー、認証失敗、設定競合からC2を確定しない |
| AsyncRAT・VenomRAT・DcRAT | 動的設定URLの`origin_only`を維持し、DcRATでは設定とprotocolの両成功後にまとめて採用 | resolver originを完全な取得先や終端C2へ昇格しない。片方の回収失敗時は先行設定を残さない |
| managed metadata・proxy | token、RID、signature、MethodSpec、field重複と全proxy recordを照合。字句的参照の走査不足をpartialへ伝播 | metadata宣言一致は実行時dispatch、framework真正性、無副作用、protector帰属の証明ではない |
| 復元層の来歴 | 原本とcompact PEを別層として扱い、宣言型変換の親を原本SHAへ結び付ける | 正規化後bytesを原本の子として誤記しない |
| 起動前監査 | AST参照を保持する3辞書cacheと、固定2consumerの完全契約bool cacheで、同じaudit内の重複計算だけを除去 | cacheは別auditへ共有せず、source・callee・receiver・未知呼出し・TOCTOU検査を省かない。dispatchは毎回確認 |
| ジョブ受付・履歴集計 | schemaのexact整数、設定要否のbooleanを検証。未レビューのclassification versionをunknownへ分離 | `true`・`1.0`・文字列をschema versionへ暗黙変換せず、不適合recordを成功率の分子・有効分母へ混入させない |
| 共有解析・C2契約 | nested解析契約、pipeline版番号、直接C2 validatorで対応値のexact整数を検証 | 型の同値受理を閉じるだけで、元outcome・URLの役割・旧versionを成功へ補完しない |
| CLRリソース宣言 | 原本bytesのPE・CLI・metadata・resource範囲と固定13tableの共有snapshotを照合 | parser viewだけの一致、部分的記述子、linked resourceを本文取得・復号・C2確認の証明へ使わない |
| CLR構築前の宣言 | exact bytes、canonical PE配置、全45tableの個別・総宣言上限を固定2consumerのparser構築前に検査 | 未対応配置・過大宣言は構築前にpartial。全parser allocation・CPU・高水準意味・C2確認の保証ではない |
| 契約内のfile参照 | 外部・UNC・Windows別名をlookup前に拒否し、全componentの非追従検査後に包含性を再確認 | 型不正やfile検査例外を完了・日次繰越へ昇格しない。強TOCTOUや敵対rootへのsandboxではない |
| 再解析計画 | 既存URL役割`unknown_structure`を修復レビューへ分離。純粋APIの未知objectを型検証で拒否 | 構造不明のURLを抽出job候補やC2確認済みへ変換しない |
| managed RAT通信仕様 | 同名method recordの重複を明示拒否。hash・PE parser前に32 MiB exact bytes入力を確認 | 重複key数・列挙順・別variant fallbackで曖昧性を隠さない。全本文走査の保証とは区別 |
| PureRAT設定の重複 | 単一ASCII hostの大文字小文字・末尾1個のdotを既存出力と同じ同値判定へ統一 | 複数hostは同値重複も含め未対応として拒否。portの順序や値、証明書、未知field、Unicode、末尾2個のdotの差は競合として拒否 |
| ValleyRATの後続層 | 未確定wide-pipe候補を保持し、既存native・SilverFox lineageの復元済み子を調べる | 不完全な子集合、未知schema、unsafe観測は添付しない。outer候補のendpointを終端へ混合しない |
| ValleyRATのraw設定候補 | 非PEの完全な反転recordだけ、marker前置文脈と設定を分離。全材料の件数・長さ・総量上限と競合拒否を維持 | raw候補をPEの定数、family、終端設定、live C2へ昇格しない。suffixや隠れたslotを切除して救済しない |
| StealC v1設定選択 | 既存RC4探索の上位4候補それぞれでlayoutを検証し、唯一の完全profileを採用 | 不完全な高スコア候補を優先せず、異なる完全設定の競合もスコアで断定しない |
| VidarのXOR設定選択 | 最大64試行の全候補を比較し、全設定・順序付きrecord・鍵SHAが一意の場合だけ採用。同値重複は先頭表記を維持 | 打切りprefix、65件目、相反profileを非採用。候補走査の完了を最終C2の確定へ使わない |
| PureRATの追加拒否境界 | nested深さ打切りと128 unique試行を成功へ戻さず、旧host／port schemaの複数hostをdecoder全体で拒否 | 先頭hostを選ばない。任意wrapperや別CHRD終端を同一候補集合と推測しない |
| StealCの同key相反 | 復号列内の完全設定とfinal 4keys内の相反をstrict内部理由で保持し、公開None互換を維持 | 既知相反後のXOR・protected・v2／endpoint fallbackで再確定しない |
| Vidarのrecord完全性 | 切断と0長fieldを分離し、最大32recordの先はURL長1byteで明示終端だけ確認 | 不完全候補を捨てて別complete設定を全viewの一意解としない。unframed境界を推測しない |
| ValleyRATのdepth完全性 | 深さ4の未証明loader候補をpartialへ閉じ、strict終端をcap前に判定 | 別branchに終端が一つあるだけで未探索branchをcompleteとしない |

通常のproduction入口は引き続き`common/analysis_job_runner.py`です。request、入力snapshot、隔離された解析process、出力の独立検証を省いてfamily scriptを直接起動する経路へは変更しません。既存のrequest schemaに新しい任意commandや通信権限は追加していません。

具体的な設定上限と証拠の境界は、[宣言型変換の予算](DECLARATIVE-TRANSFORM-BOUNDS.md)、[managed RAT設定の安全境界](MANAGED-RAT-CONFIG-STATIC-SAFETY.md)、[managed handler回収契約](MANAGED-HANDLER-RECOVERY-CONTRACT.md)、[metadata参照の検証](../../docs/MANAGED-METADATA-REFERENCE.md)を参照してください。

起動前監査の重複計算については、[cache修正の範囲と比較結果](STATIC-PREFLIGHT-CACHE.md)を参照してください。限定した3件の相対計測を、全検体の抽出率や処理時間へ一般化しません。

追加の設定選択と打切り拒否は[ファミリー別の証拠境界](STATIC-CONFIG-SELECTION-BOUNDARIES.md)にまとめています。対応しているschema内で候補を安全に選ぶ改善と、未知schema／実行時の全設定を証明することは区別します。

固定sourceがGitの改行変換で拒否される包装上の問題には、[9file限定の改行保持](STATIC-SOURCE-PACKAGING.md)を追加しました。source pinや解析権限は緩めず、現worktreeのraw bytesを保持します。包装回帰10件と、適用しない人工patch5対照を別途確認しました。既存indexの自動修復や公開済みblobの照合を済ませたとは扱いません。

## 過去の未完了記録を改善につなげる

履歴の読取監査と再解析計画は、実解析の実行とは分離しています。両方とも検体を開かず、C2やdead-dropへ接続せず、結果を更新せず、jobを自動dispatchしません。

リポジトリrootから履歴監査を行います。

```powershell
python -I -X utf8 -B .\analysis-framework\common\automation_failure_inventory.py --repository .
```

出力は標準出力のJSONです。`-X utf8`でWindowsの既定code pageによる文字化けを避けます。保管する場合は管理された非公開保存処理を使用し、公開レポートやGitへの追加対象から分離してください。以前のinventoryとの比較には`--baseline`を使用します。この比較用baselineは監査対象リポジトリ内の安全なmetadata JSONに限り、認証情報を指定しません。baselineがなければ`comparison_unknown`であり、変更されたと推測しません。

保存済みinventoryから、人間レビュー用の有界な再解析計画を生成できます。

```powershell
python -I -X utf8 -B .\analysis-framework\common\automation_reanalysis_plan.py `
  --repository . --inventory C:\analysis-private\inventory.json `
  --max-candidates 64 --max-repairs 128
```

plannerは現在のcatalogとmetadataを再読込して、入力inventoryのidentity、全投影field、fingerprint、自己commitmentを照合します。差分があれば計画を拒否するので、最新inventoryを取り直します。保持数を超える候補は黙って消さず、省略件数と省略内容のcommitmentを返します。

| 計画の分類 | 意味 | 次の扱い |
|---|---|---|
| `static_remediation_candidate` | 現契約の記録と証拠が揃い、登録済みblockerから静的な次手順を選べる | 対象範囲と現在実装の一致をレビューしてから別の解析workflowを作る |
| `metadata_repair_review` | 旧形式、欠落、未知blocker、identityやfingerprint不足など | 記録を確認し、検体解析の失敗と混同しない |
| 次手順なし | この監査が扱う改善actionが記録されていない | 検体やC2の全解析完了を意味しない |

`automatic_dispatch_allowed`、`automatic_retry_allowed`、`same_workflow_resume_allowed`は許可へ変換しません。保存された解析契約は現在の実装との一致証明ではなく、同じworkflowの強制resumeを行う根拠にもなりません。詳細は[履歴監査](AUTOMATION-FAILURE-INVENTORY.md)と[再解析計画](AUTOMATION-REANALYSIS-PLAN.md)を参照してください。

## 検証結果の読み方

性能cache修正前の固定snapshotで、アンパッカー・静的レイヤー・Settingsの統合869件、および一括入口・候補確認・handler・履歴監査・plannerの統合794件が成功しました。性能修正後は、固定managed依存・handler・cacheなどの167件と、短い一時pathを使うfixture・既存path長guardの14件が成功し、一括入口を含む広い回帰643件も成功しました。その後のジョブ受付の型検証は新規・既存15件で確認し、履歴集計・planner・受付の回帰211件、protocolの回帰66件も別snapshotで成功しています。protocol修正後のhandler等119件、共有契約修正後のpublisher・C2・corpus・inventory等268件も成功しました。この時点のsourceを固定した広域回帰25ファイル954件は1139.63秒で成功しています。続くPureRAT修正は通常extractor・新規同値判定・managed handler契約の65件で成功しました。これらは人工fixtureと通常コードの回帰試験です。suite間には重複があり、合算して独立検体数や検体成功数にはしません。

PureRATの新規試験には、実際のCLI headerと`#US` heapを持つ人工PEから通常入口を通す例を含めました。同じhostの表記差で従来は設定競合になった例を回収でき、単一設定の出力契約も維持します。人工PEは命令の実行に用いず、この結果を本物の検体の成功率、独立family確認、C2稼働確認へ一般化しません。

ValleyRATの追加130件では、候補が既存のstrict終端復元を遮らないこと、確定wide設定と先行profileの優先順位、route-onlyの非昇格、候補objectの再利用時の非混入を検証しました。復元子の再抽出結果はactual bytesのSHA-256と安全flagも照合し、不一致は既存の例外として拒否します。この機能は新しい暗号・任意命令の実行器を追加せず、既存の静的復元を接続するものです。

その後、candidate確認とone-shot設定投影の追加統合では14件成功・1件失敗でした。raw XOR設定のmarkerとrecordが同じprintable文字列にある旧fixtureの期待と、exact文字列境界判定が一致しないことを確認しました。この欠落は、共有parserを緩めずraw専用helperを3入口だけへ接続して修正しています。通常のraw・上限・mapped data-flow回帰136件が4.15秒、以前失敗した分類連携を含む15件が229.11秒で成功しました。mapped PE内のprefix付き・中途切断のrecordやpublic exact APIの拒否条件は変更していません。

raw専用helperは切除前に100,000文字列、単体8,192文字、総4 MiBを検証し、型不適合、隠れた順向き・逆向きslot、異delimiter、末尾欠落、suffixを救済しません。`raw_candidate_scan_complete`は当該文字列材料の走査だけを指します。分類器はroute候補を得てもfamilyをunknownのまま保ち、設定の確証・終端payload・C2稼働確認を付けません。

StealCでは、人工PEの実Base64・RC4処理を含む新旧45件と、通常2handlerの静的起動前監査2件が成功しました。profileの全7設定・証拠fieldで競合を判定し、同値の候補は最初の表記を維持します。最高得点の不完全な候補が、既存閾値とlayoutを満たす候補を遮る例を回収できました。初回の起動前監査は新しいdict methodを拒否したため、一般許可を増やさず同値のmembership・代入へ変更して再検証しています。

この段階のStealC修正は512鍵・64 probe・4 final・4096符号化値の既存探索内だけの改善です。未探索候補の不存在や、全PE parser・候補文字列集合の材料化まで有界化済みとは主張しません。この段階ではURL validatorや他方式へのfallback、v2対応、独立family確認、C2稼働確認の条件は変更していません。後続の既知相反fallback停止は別の追加修正です。

Vidarでは、新規40件を含む通常のstealer・compact・意味付け回帰53件が2.51秒で成功しました。最初の有効profileで打ち切らず、後方の相反設定も非採用にします。`xor_config_assessment`は固定理由、件数、走査完了、一意性だけを保持し、競合と上限打切りを区別します。公開`recover_xor_config`の失敗時は空dictのままで、診断objectを成功と誤読させません。

このVidar修正は、初回にはAST起動前監査だけ通り、検体なし隔離importは両方`runtime_import_failed:HandlerLoadError`でした。同一source・symbolでも別経路でimportされたmodule名の不足を修正し、補完対象を既存のimport本文監査済みsourceに限定しました。未監査sourceを補完する反例は拒否します。通常の人工import監査33件とVidar両入口の隔離import2件は28.72秒で成功しました。compact viewの独立64 MiB上限は、compactor内部・元入力材料化・全PE parse・wall clockを新たに有界化したという意味ではありません。既存32record grammarとURL役割は不変で、dead-dropの取得やC2への接続は行いません。

resource依存・namespace補完・C2型検証を含む9月28日03:23のsnapshotでは、全92familyの宣言110handlerについて、1051回のformat別AST監査と110回の検体なし隔離importを実施し、全110入口が通りました。開始前・終了後のsource指紋は一致しています。detectorと品質policyまで揃う構造は82family、candidate-onlyは8family、detector無しのmanual対象は2familyです。この後の追加修正には別の最終再検証が必要です。

この結果は起動前の実装契約と接続可能性の検査です。全handlerが本物の検体でfamilyを確定し、設定を抽出できたという意味ではありません。89.13%は構造の割合であり、実検体の抽出率ではなく、`automated_analysis_completion_verified`は0のままです。監査が「設定確認済み」と数える記録も、分母は現在のreport契約に適合し、設定が必要と記録されたcaseだけです。旧記録や候補を除外せずに全検体の成功率へ一般化してはいけません。

## 9月28日の最終固定版

追加の設定選択修正は、候補sourceの全文監査、別担当者のread-onlyレビュー、通常moduleでの人工回帰を経て採用しました。PureRATのdepthと単一host、新旧抽出とmanaged契約は124件が2.48秒、Vidarのrecord終端・候補選択・意味付け・隔離importは92件が33.54秒、ValleyRATのdepth・KBND footer・strict子選択は99件が1.76秒で成功しました。先行するPure／StealC／Valleyの135件は9.92秒で成功しています。これらは互いに重複する試験集合なので合計して独立検体数にはしません。

採用した通常5fileは候補と全ASTが一致し、Pure／Valley／Vidarは改行正規化全文も一致しました。StealC2fileはcandidate末尾の空行1行だけが異なり、codeやdocstringの差はありません。全文exactの5file一致と誤記せず、未知差分なしという結果を区別します。Vidarの作者による機械対照は、別担当者の設計レビューの代わりにはしません。

最終実装のcommitmentは981files、13,845,744bytes、manifest SHA-256 `d4598beb2e545773e8abb5584b790374fa6e134431cf5c118719321593a303a3`です。このsourceを固定した全110handler／1051formatのAST監査と、検体なし隔離import110件は全件成功しました。成果物の再生成と`--check`の別実行もexit0で完了し、それぞれ終了後のsource指紋は一致しています。同じ入口の再検証を独立検体数として倍増させません。77file・3,053人工caseの広域回帰は1935.59秒で全件成功し、exit0で終了しました。JUnitも3,053件・失敗0・エラー0・skip0を確認し、終了後のsource指紋は同一です。既存の部分集合の成功数を、この広域回帰へさらに加算しません。

この981fileの実装commitmentは`tests`ディレクトリを除外します。77test fileのsize／SHAは試験終了後の別記録として捕捉し、試験開始前のbyte指紋と同一だったという遡及的証明には使いません。

以前の68／71file広域実行は、source採用の区切りで中断したため完走扱いしません。長い一時pathによるCLI smoke失敗と兄弟module importの収集失敗は、製品の安全上限を緩めず試験側を修正し、専用の再検証結果とともに履歴へ残しています。

包装説明を含む対象16日本語文書は言語監査0findings、変更対象14API moduleは生成内容との同期確認済みです。これらも実検体のfamily確定率やC2抽出率とは別の検証です。

## 保証範囲と未統合の機能

CLR resource descriptorの共通化は通常sourceへ反映し、人工raw PEを含む363件と既存metadata・unpacker等358件で確認しました。初回起動前監査119件は118件成功・AsyncRATの深さ制限1件失敗でした。同じsource内の能力列挙に余分な依存edgeを数える箇所だけを修正し、固定深さ12・真のsource間依存・全callee本文監査は維持しています。修正後は監査127件と深さ陰性13件の計140件が902.87秒、ValleyRATの既存拒否境界28件も196.02秒で成功しました。境界と未保証範囲は[resource入力の検証](MANAGED-RESOURCE-INPUT-BOUNDARY.md)を参照してください。

成果物のpipeline版番号では、floatの`2.0`を整数版`2`として受理する人工反例を確認しました。exact整数に限定する1箇所の修正後、公開処理・snapshot・C2契約の179件が72.67秒で成功しました。対応する正常版、旧版・欠如の拒否、元の品質状態の非変更を検証しています。

C2契約のenumが配列・objectだった場合、従来は集合との比較で例外停止する10例を確認しました。phase・終端状態・outcome・確度・優先度の型を先に確認し、固定findingで不適合として返すよう修正しました。元の正常契約・未解決の繰越条件は維持し、不正なoutcomeは`invalid`です。公開・履歴集計を含む233件が73.06秒、最終assertを含むC2契約42件が1.21秒で成功しました。これはJSONの型不適合を扱う改善で、任意Python objectへのsandboxや全JSON readerの有界化ではありません。

追加の独立監査では、終端状態の型不正が正常な未解決と同じfindingに合流し、日次繰越を許していた7例も確認しました。非文字列・欠如の状態を`terminal_payload_status_invalid`へ分け、型不適合は繰越可能にしません。文字列の正常な未解決や元のoutcomeは維持します。通常C2契約・公開処理・履歴集計の240件が80.54秒、3 outcomeを比較する独立人工24件が0.50秒で成功しました。

constructor前のmetadata宣言予算は固定2consumerへ採用しました。通常配置の宣言149件、canonical配置29件、写像対照33件に既存triage・API回帰を合わせた234件が7.35秒で成功しました。短い壊れたPEは旧parser例外ではなく構築前partialになり、正常構造の人工PEでparser例外の検証も維持しています。詳細は[構築前検査](MANAGED-CONSTRUCTOR-PREFLIGHT.md)を参照してください。

constructor依存93件、resource依存133件、深さ13件、namespace33件の通常272件は、cache前1786.86秒、cache採用後1645.14秒でそれぞれ成功しました。実行時の並行負荷が異なるため、この差を厳密な速度比較には使いません。監査内cacheの通常22件は成功し、global入口の完全契約の毎回検査、別auditでの再判定、契約例外の非保存、dispatchの毎回検査、source pin・callee・depthの拒否を確認しています。局所計測は[cache修正の範囲](STATIC-PREFLIGHT-CACHE.md)に分け、実検体の抽出率とは扱いません。

Windowsの長い一時pathが人工CLI smokeの製品側path長拒否に触れたため、試験だけを短い専用rootへ移しました。入力snapshotのreadonly保護は試験中ずっと維持し、専用fixtureの終了直前に、固定した人工fileの包含性・通常file・single link・非reparseを確認して後片付け可能にします。製品のpath長上限、readonly、改ざん検知、入力契約は変えていません。smokeは124.96秒で成功し、この後片付け境界の6件も成功しました。広域test収集での兄弟module importの問題も、固定した通常test fileの読取に限定して修正しました。

通信仕様の有界reader、strict回収失敗の秘密値を含まない診断集約、静的C2段階とlive follow-up段階の別projectionは、別単位として互換性と陰性試験を検証中です。これらの試作結果を通常入口へ統合済みと扱いません。実dnfileのconstructor allocation、暗黙の全table parse、source-boundな証拠、旧schemaのunknown維持は個別に検証し、source hashだけで安全としません。

PureRATには、`#US`走査の予算打切り・heap破損とraw文字列fallbackの証拠境界が未解決として残ります。fallbackは独立resource readerではなく入力全体の文字列走査であり、成功時にmetadataの不完全性が下流へ伝わらない場合があります。広域回帰の成功はこの残件の解消証明ではありません。具体的な現動作と次の検証条件は[ファミリー別の証拠境界](STATIC-CONFIG-SELECTION-BOUNDARIES.md#検証と残件)に記録しています。

この機能単位の検証では追加検体の取得、実検体の読込み・実行、受信payloadの実行、外部C2接続は行っていません。未確認の設定、終端payload、protocol、稼働状態を「完了」にする変更も行っていません。

## 時間枠の終了

日本時間2026年9月28日06:00の期限で継続自動化を停止し、保存されたPAUSED状態を確認しました。検証した実装・文書は作業コピーに保持しています。これは本機能単位の引継ぎであり、上記の未解決事項や実検体での抽出率評価まで完了したという意味ではありません。staging、commit、push、PRは行っていません。
