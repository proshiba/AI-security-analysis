# 静的 unpacker

この directory には、共通の上限付き unpack pipeline があります。検体、復元 payload、installer callback、script、packer stub を起動せず、抽出したインフラへ接続することもありません。

## 対応する復元経路

| Layer | 静的方法 | 結果 |
|---|---|---|
| ZIP/7z/RAR とCABの外部fallback | 上限付き 7-Zip inventory と抽出 | 保持対象 member と再帰解析 |
| CAB (None/MSZIP) | 宣言件数・size・offsetを事前検証後、`cabarchive`でmemory展開 | 検証済みmemberと再帰解析 |
| CAB (LZX) | 単一volume、window、全CFDATA checksum、path・size・境界を事前検証後、`binary-refinery`でmemory展開 | 検証済みmemberと再帰解析 |
| NSIS | NSIS 対応 7-Zip による script decompile | `[NSIS].nsi`、member、明示された script 変換 |
| NSIS hexadecimal XOR stream | `IntOp` と `IntFmt %08X` の word decode を再現 | System plugin の call stream |
| NSIS native XOR loader | 上限付き x64 定数伝播後に dword XOR | 実行しない中間 loader |
| PyInstaller CArchive | cookie／TOC／全entry境界・path衝突・圧縮stream終端・実sizeをmemory上で検証 | script、module、PYZ、PE、入れ子archiveの優先保持と全inventory commitment |
| UPX | 隔離した入力に対して信頼済み UPX utility を実行 | UPX が file を検証できた場合の unpack 済み PE |
| PE resource と overlay | offset と size を parse し、有効な PE 範囲を carve | child PE/resource |
| RTF `objdata`／OLE1 Package | RTF group、hex、OLE1 embedded object、Ole10Nativeの全境界を上限付きで検証 | 宣言拡張子を信用しない内包payloadと部分失敗report |
| 暗号化OOXML／Equation Editor OLE | Office既定パスワード、hidden worksheet、Equation CLSID、native stream、x86 CFG、LCG XOR、復号stageのAPI／URL／保存先を有界検証 | 復号OOXML、VBA source、検証済みdownloader stage |
| Go Windows AMD64の明示的な5段byte変換 | Go1.20以降のpclntab、関数境界、定数copy、review済み数学blockのregister幅・使用関係・順序を照合 | 親子SHA-256付きの構造検証済みPE候補 |
| PE `.data` の逆順fragment＋affine XOR Donut wrapper | `.data`末尾のkey／size、4・8分割の境界、zero padding、既知Donut loader prologue、復号instanceを上限付きで照合 | 認証済みDonut shellcodeを子レイヤーへ送り、終端moduleを再帰解析 |
| GDPF PDF overlay | EOFのlittle-endian size、GDPF footer、PE overlay境界、%PDF- magicを同時検証 | 実在する場合だけPDFデコイを子レイヤー化 |
| .NET ResourceSet | object を deserialize せず serialized resource を parse | string、byte array、image |
| .NET single-file bundle | manifest境界、圧縮終端、宣言sizeとSHA-256を照合し、固定件数・byte上限内で選定 | 本体・設定・依存候補と、省略理由付き全entry台帳 |
| .NET resourceのTripleDES-CBC＋4-byte prefix付きGZIP | framework API署名、CIL local定義・使用、正常CFG、16/24-byte keyとAssembly.Load sinkを照合 | 独立した子解析へ渡すPE/CLR境界検証済み候補 |
| .NET bitmap steganography | 上限付き RGB column traversal を再現 | 埋め込み managed PE |
| .NET Bitmap RGB→ARGB/XOR loader | outerのx-major RGB、3引数constructor、第一exported typeのreview済みCIL、限定NRBF、単一PNG、crop、BGRA、length、UTF-16BE周期XOR、Assembly.Load sinkを照合 | exact Assembly.Load bufferをprivate再帰解析へ渡し、PE extentを別途記録（family／C2／終端確証には不使用） |
| AutoIt A3X | script が手順を明示する場合に literal、RC4、LZNT1 を decode | 埋め込み PE |
| JavaScript string array 難読化 | array を parse し、rotation を解き、alias を decode して literal を畳み込み | 可読化した script と URL |
| JavaScript逆順・区切り文字挿入Base64 | 長大literalを反転し、Base64外の複数separatorを除去して構造を検証 | Lua layerとPE |
| UTF-16 JavaScript dropper | numeric array、repeating Unicode key 変換、environment chunk を畳み込み | PowerShell と terminal PE |
| Environment分割型JScript loader | 区切り文字付きBase64、HKCU Environment分割、`Assembly.Load`、暗号化19引数をprofile拘束で照合 | managed loaderとpayload取得URL候補 |
| JavaScript AES/GZip chain | 埋め込み AES-CBC key/IV と GZip 手順を parse | terminal managed PE |
| Batch／PowerShell／JavaScript polyglot | `set "PREFIX..."` chunk、size／SHA-256 metadata、custom nibble、単一byte変換、AES-CBC／PKCS7／GZipの受渡しを照合 | 検証済みPowerShell、補助PE、HOI1 inventory、KMTA内包PEまたは未解決blocker |
| PowerShell回転位置付きXOR | 3式の完全一致、Base64 here-string、32 byte key、modulo 7更新、単一script候補を照合 | 再帰静的解析用script（family／C2確証には不使用） |
| managed Eaz keyed resource | flattened switch、定数key／mask、build固有word変換、partial word、raw DeflateをCILから照合 | resource-only managed PE（終端／family確証には不使用） |
| CMD echo Base64 stream | target 別に redirection をまとめ、chunk を連結して検証 | fragment noise を除いた terminal PE/archive |
| Jadoo split bundle | manifest の offset と length を検証 | 再構築した file |
| 宣言型byte変換sidecar | 許可リスト方式の回転、XOR、反転、sliceを適用し、Donut、magic、PE、ZIP構造を検証 | 検証済みchild layerと再帰解析されたterminal payload |
| 一般的な base64/hex | size と format を gate とする decode | child layer |
| Mach-O | header と segment の inventory | packing 評価だけ |

`static_unpacker.py` が orchestrator です。`javascript_obfuscator.py` は script encoding と string array layer、`javascript_dropper_unpacker.py` は numeric array、Unicode environment、AES-CBC、GZip chain、`javascript_reverse_base64.py` は逆順・複数separator付きBase64 literalを処理します。`javascript_env_assembly.py`と`managed_win32_rmp_loader.py`は、Environment分割型JScriptからmanaged loaderを復元し、確認済みmethod body／resource profileだけで19引数の設定を復号します。`batch_powershell_polyglot.py` はBatch comment内のcarrierを収集し、同梱metadataのsizeとSHA-256へ一致する成分だけを昇格します。`nsis_unpacker.py` は明示的な NSIS script と native constant XOR layer を処理します。`static_control_flow.py` は、上限付きの再帰的 x86/x64 entry CFG triage を提供します。`opaque_native_entry.py` はimportless native PEに限定し、entry CFG、PEB／export resolver、API hash候補、変換loop、埋込みPE候補を実行やCPU emulationなしで調べます。byte走査の完了と意味的な復元完了を分離し、未知hashや動的pointer tableが残る場合は完了扱いにしません。候補関数、追跡関数、resolver callsite、変換loop、API／module hash、entry CFG、埋込み候補は`total`、`returned`、`truncated`で記録し、いずれかの上限到達を`coverage_complete=false`へ反映します。`managed_il_triage.py` は CLR を load せず、managed metadata、CIL、resource を棚卸しします。`managed_proxy_deobfuscator.py` は埋込みresourceのhash・entropy・保護候補を列挙し、確認済みEazfuscator系DynamicMethod proxy表をfield→methodの対応へ静的復号します。

`rtf_objdata.py`は、32 MiB以下のRTFをgroup depth 256、`objdata` 32件、native data 16 MiBの範囲で完全走査します。control word、`\bin`、nested groupを区別し、OLE1 version／format、長さ付き文字列、native境界を検証します。`Package`ではOle10Nativeの各NUL終端文字列、temp path長、payload長も検証し、宣言された`.pdf`等の拡張子では内容を分類しません。複数objectの一部が壊れている場合は検証済みobjectだけをSHA-256で重複排除し、`partial_artifacts_recovered`として固定点解析へ渡します。RTFや内包payloadは実行しません。

`office_encrypted_package.py`は、拡張子に依存せず、OLE内に
`EncryptionInfo`と`EncryptedPackage`が共存する暗号化OOXMLだけを対象にします。
Office既定パスワード`VelvetSweatshop`を1回だけ検証し、一致した場合は復号結果が
`[Content_Types].xml`と`_rels/.rels`を持つ有効なOOXML ZIPであることを確認してから
固定点解析へ渡します。辞書探索、Office起動、macro実行、外部通信は行いません。
入力64 MiB、復号結果128 MiB、OOXML 4096 memberを上限とし、password値はreportへ
出力しません。

`office_vba.py`はOLE container内のVBA sourceを`oletools`で静的に復元し、
各moduleを固定点解析へ渡します。p-code、VBA、Office applicationは実行せず、
入力、module数、module単体size、復元総量のいずれかが上限を超えた場合は、
その入力からの復元物を一切採用しません。parser由来のstream名とmodule名は
公開reportへ直接記録せず、照合用SHA-256だけを残します。

`equation_ole.py`はXLSX、Equation OLE compound file、またはraw native streamを入力にし、
Equation Editor CLSIDと一意な`\x01OLe10nATive` streamを確認します。`0x50`から到達する
call/pop型PIC decoderを有界CFGと定数伝播で追い、stage境界、LCG更新、dword XOR、
loop終端が一意な場合だけ復号します。復号後もstack確保、module／API集合、単一URL、
単一保存先を再検証し、構造が曖昧な場合はartifactを返しません。命令実行、CPU emulation、
Office起動、外部通信は行いません。`static_unpacker.py`のZIP／OLE分岐へ統合され、
暗号化XLSXの復号後も固定点解析で自動到達します。

`batch_powershell_polyglot.py` は入力16 MiB、16,384行、単一行2 MiB、metadata 32件、carrier prefix 4,096件、候補work 64 MiB、metadata入力work 128 MiB／展開出力work 64 MiB、hex変換work 128 MiB、単一復元成分32 MiBを上限とします。Base64はstrict decode、GZipは単一stream終端・trailing dataなし・展開比512倍以下を要求します。custom nibble経路は16文字の一意なalphabetとmetadata hashを、AES経路は復元PowerShell内の共通XOR付きkey／IV配列、CBC、PKCS7、RSC変数の同一callへの受渡し、復号後GZip、PE全section境界を同時に検証します。reportへ生key／IVを出しません。metadata検証済みPLDを`native_kmta_loader.py`で一意に復元できない場合だけ、`metadata_verified_pld_requires_native_loader_analysis`をblockerとして残します。

`powershell_rotational_xor.py` は入力16 MiB、here-string 32件、Base64 12 MiB、復号後8 MiB、keyとciphertextの総復号work 64 MiBを上限とし、レビュー済み式と一意な32 byte key／scriptの組だけを受理します。`managed_eaz_resource.py` は入力32 MiB、MethodDef 4,096件、各256 KiB・8,192命令、1 method当たりの追加section合計256 KiB・4,096件、全method合計32 MiB・1,000,000命令、resource 64件、復元後64 MiB、展開率64倍をhard limitとし、MethodDefの宣言bodyと追加sectionが同じPE section内に収まることもparser呼出し前に検証します。処理境界では10秒の協調的deadlineも適用します。いずれも検体や復元物を実行せず、生key／maskをreportへ含めません。

`managed_bitmap_argb_xor.py` はroot hashやprovider labelを受理条件にせず、outer CILのwidth外側／height内側の`GetPixel(x,y)`、RGB順、`Take`、同じlocalを通る`Assembly.Load`、field literalから作る3引数と同一`ConstructorInfo.Invoke`までを照合します。第一段childでは19個のreview済みmethod bodyに加え、同一owner、第一exported type、publicな3文字列constructor、constructorからentryへの引数受渡し、framework参照、call graph、crop 2定数、末尾由来mask定数を検証します。BinaryFormatter／CLR／CILは実行せず、NRBFはcanonical 7-bit整数と固定record列だけをbyte単位で読みます。Bitmapは単一のBMPまたはCRC・chunk順・zlib終端を確認したRGBA8 PNGに限定し、crop後のx-major BGRA、little-endian length、UTF-16BE key byte列を文字列長で循環するXOR、managed PE extentと最大4 KiBのoverlayをすべて確認します。

同経路の上限は入力32 MiB、MethodDef 8,192件、method単体256 KiB、method合計16 MiB、命令合計250,000件、ResourceSet 256件、entry 4,096件、resource合計32 MiB、Bitmap 16 MiB、画像1辺4,096・8,000,000 pixel、PNG chunk 4,096件、圧縮32 MiB、画像work 64 MiB、復元出力64 MiB、協調的deadline 10秒です。exact `Assembly.Load` bufferだけを`private_recursive_analysis_only` artifactとして保持し、公開reportへraw resource、payload、constructor引数、key、mask、短い名前のhashを含めません。reportのfamily／C2／terminal昇格flagは常にfalseであり、復元成功をPureHVNC、PureRATその他のfamily根拠へ読み替えません。

`native_kmta_loader.py` は、x64 PEのexport codeからRIP相対の1-byte memory参照を静的に列挙し、非実行section内の連続48-byte参照だけをAES-256 key／IV候補にします。実行section内の`KMTA`比較、PKCS7、headerとANSI／UTF-16 path長、child PEのexact file extent、AMD64、ImageBase、SizeOfImageが全て一致し、候補payloadが一意な場合だけ復元します。loader 32 MiB、ciphertext 64 MiB、export 256件、命令100,000件、候補64件、復号work 256 MiBを上限とします。生key／IVはreportへ出さず、materialのRVAとSHA-256だけを記録します。命令実行、CPU emulation、外部通信は行いません。

`managed_handoff_image.py` は、`Reflection.Emit` loader向けの`HOI1` serialized imageをCLRへloadせず完全走査します。namespace、main class、data blob、type、field、method、parameter、local、CIL、token fixup、例外領域のcount・length・offsetと入力終端を検証し、fixup種別とUTF-8 string literalを上限付きで棚卸しします。入力32 MiB、type 2,048件、field／method／parameter各65,536件、CIL合計24 MiB、blob合計32 MiB、fixup 262,144件を上限とします。これはserialized metadataの構造確認であり、CILの実行、Reflection.Emitによる型生成、native loaderの起動、family／C2の確定ではありません。

`reverse_chunk_affine_xor_donut_pe.py` は、`.data` に一意な候補と認証済みDonut instanceがある場合だけ子shellcodeを返します。復元されたshellcodeと終端moduleは `static_layer_pipeline.py` が親子SHA-256を付けて再帰解析します。Donutの既知prologueとinstanceの検証は両方必要で、wrapper構造だけをfamilyまたはC2の確定根拠にしません。

`go_embedded_pe.py` は、Windows AMD64のGo wrapperにある明示的なcopy source、size、literal prefix、decoder callと、レビュー済みの5段変換（偶奇byte変換、全体反転、隣接交換、index依存減算、index依存XOR）だけを静的に再構成します。検体SHA、module名、関数名の乱数部分、鍵の一覧には依存しません。命令の実行、CPU emulation、ネットワーク、外部process、ファイル書込みは使用しません。復号先はPE header、全sectionのfile境界、AMD64、実行可能section内のentryを再検証します。入力32 MiB、出力8 MiB、関数8,192件、関数body512 KiB、names領域1 MiB、候補table8件、copy候補4件、経過10秒を上限とし、曖昧なcopyや演算blockの変更は拒否します。reportは演算blockのRVA、親子hash、sizeだけを残し、生鍵・復号byte・元module名を公開しません。復元はchild候補の取得であり、制御フロー全体の意味的完了、終端到達、ファミリー確定、C2確認ではありません。Goという言語や包装形式だけからmalware familyを推定しません。

collection単位の再開では `analysis-framework/common/collection_followup_planner.py` が、公開済みreportの契約と登録済みblockerだけを読み、未完了caseを再試行可能性別に分類します。同一証拠で解消できないblockerは無益に再実行せず、新しいterminal evidenceまたは対応実装を待つ計画として残します。

CABはparserを呼ぶ前に`MSCF` headerとversion、予約field、cabinet実size、単一volume、folder・file・data block件数、file/folder offset、宣言size、path衝突を検証します。None/MSZIPはこの予算検証後に`cabarchive`へ渡します。LZXはwindow 15–21と全blockの非zero checksumも検証し、`cabarchive`が正確に`LZX compression not supported`を返した場合だけ`binary-refinery`へ切り替えます。LZX固有のpeak memory事前判定は、入力CAB、全folderの復号cache、全memberの`bytes`化、最大decoder window、member・folder・block metadataを合算し、さらにPython runtimeと周辺解析用に256 MiBを予約します。この保守的な見積りが1 GiBを1 byteでも超える場合はdecoder起動前に拒否し、判定内訳と残余byte数を正常時の機械可読contractへ記録します。展開後もfolder/member sizeとmember tableを再照合し、全条件が一致した場合だけ結果を保持します。一時file、外部process、検体・payloadの実行、network通信は使わず、検証失敗時に7-Zipへ迂回しません。checksumを持たないLZX CAB、multi-volume CAB、Quantum圧縮、重複pathは安全側に拒否します。

PyInstaller CArchiveは最大16,384件（hard limit 65,536件）のTOCを先に全検証します。既定budget内では全entryを1件ずつ展開してzlib EOF、宣言size、実size、SHA-256、形式を検証し、非候補bytesは直ちに破棄します。archive全体を自動解析する`analyze_carchive_bytes()`で後段へ保持する候補は最大256件で、caller指定、Python script、module、PYZ、PE名候補、入れ子archiveの順です。一方、名前またはprefixを指定する`extract_selected_entries_from_bytes()`、`analyze()`、standalone CLIの`--max-files`は既定・hard limitとも128件を維持します。256件への拡張はarchive全体の自動候補保持だけに適用され、選択抽出APIの契約を広げません。1 entryは64 MiB、保持総量は128 MiB、全内容検証は256 MiB／120秒を上限とし、超過や高価値候補の未保持は`partial`とblockerへ残します。公開reportは全entry列ではなく件数・形式集計とinventory/content commitmentを持ち、PyInstallerという包装形式だけからmalware familyや悪性意図を推定しません。

`dotnet_bundle_unpacker.py`は、本体・設定、観測済みのruntime内容不整合、非runtime依存、予算不足または未対応profileで未評価のruntime、内容整合を確認したruntime、形式確認済みsymbolsの順で候補を選定します。予算で未評価だったことを内容不一致や安全確認へ読み替えません。parser拒否、metadata不正、未知statusは高優先のままです。32候補／128MiBの選定上限、64件／128MiB／単体32MiBのruntime内容probe上限を維持し、未選定entryのSHA-256・size・省略理由と`selection_complete=false`を残します。復元と構造照合は、ファミリー特定・C2取得・全解析完了を意味しません。

TOCの`typecode=s`かつname領域が先頭NULの匿名scriptは、TOC順序に束縛した合成名で保持します。元name領域はsizeとSHA-256をinventory commitmentと保持metadataに残し、不透明bytesはpathとして解釈しません。通常名の不正padding、script以外の匿名entry、path衝突、payload境界違反、不正zlib streamは引き続き拒否します。

CABなどの展開後に保持対象memberがない場合、Inno side-loadingの関連付けは`not_candidate`として記録します。空集合を`member_limit_blocked`へ誤分類せず、実際のmember上限超過は別に保持します。

PE imageの直後1 MiB以内にある`Nullsoft`または`Inno Setup` markerは、image内のUPX等のpacker markerと分離してinstaller候補にします。markerだけでは外部parserを開始せず、検証済みloader構造を持つInno候補で、信頼済みinnounpが設定されている場合はinnounpによる一覧化、`install_script.iss`の検証、選択復元を先に行います。innounpのinventoryが完了した場合は同じ入力を7zzで重複処理しません。innounpが未設定またはinventory未完了で信頼済み7zzが設定されている場合は、7zzの境界付きinventory／静的展開へfallbackします。初回の構造判定では未確認でも7zz inventoryからInnoが確認され、innounpをまだ試行していない場合は、innounpの選択復元も追加する併用経路になります。parserが対応しないinstallerは空の成功へせず`container_parser_unavailable`として残します。member件数だけでなく宣言総量が上限を超えるarchiveも、app本体、script、設定、PE等を上限内で選択復元します。

Go復元では、数学blockの存在順だけでは受理しません。`go_decoder_shape.py` がdecoder全本文の連続coverage、命令位置・size・opcode、hardware register幅と使用関係（単項imulの暗黙RAX/RDXを含む）、全内部branchの相対target、Go関数表へ結び付けたruntime callを照合します。有界compiler switchは比較上限と全jump-table targetをfile-backed bytesから検証し、table改変も拒否します。`profiles/go_decoder_shapes.json` のレビュー済み全本文fingerprintと数学blockの両方へ一致する場合だけ復号します。runtime.printint/uint直前の一回の印字literal以外の即値は保持します。全mathをskipする分岐、追加byte演算、未知callee／compiler形状は、出力PEが成立しても拒否します。この保守的なregistryは対象SHAや鍵の特例ではありませんが、未レビューの難読化variantを広く復元できるという保証でもありません。

## 使用 tool

`managed_tripledes_gzip.py` は、literal resource、Base64の16/24-byte keyと8-byte IV、CBC/PKCS7の設定を同じlocalの定義・使用に結び付けます。framework AssemblyRefの名前・公開鍵tokenとMemberRefの完全signatureを検証し、同名の検体内methodや`Assembly.Load(string)`を解釈しません。`TransformFinalBlock`と`CryptoStream`のread/copy方式に対応し、4-byte prefixを除いたMemoryStream、GZipStream、正のread件数をwriteするloop、`ToArray`から`Assembly.Load(byte[])`への受渡しが必要です。正常CFGで各localの一意な定義が使用を支配することを検証し、迂回branch、配列への未レビューの変更・alias、曖昧なresource、重複／file外のresource範囲を拒否します。

入力32 MiB、resource4 MiB、復号出力8 MiB、method4,096件、単一body256 KiB、body合計2 MiB、resource256件、各参照表16,384件、経過10秒が上限です。GZIPのprefix宣言長、単一stream終端、PEの全sectionとCLR metadata境界を再確認します。prefixの検証は静的container検証であり、親コードが長さを実行時検査したという意味ではありません。例外経路の意味的完了は保証せず、復元結果だけでfamily、C2、終端到達を確定しません。親子hash、size、MethodDef token/RVA、sinkと必要命令のbody offsetを記録し、生key／IV、resource名、復号byteは公開reportに含めません。検体・CIL・CLRの実行、CPU emulation、通信、外部process、file書込みは行いません。

推奨する7-Zip binaryはNSIS decompile対応buildです。innounpは同伴DLLを必要としないself-containedな配布物を使用します。いずれも信頼済みの静的archive／installer parserとしてだけ使用し、installerや復元memberは実行しません。

外部toolは`PATH`から探索せず、絶対pathで明示した通常fileだけを使います。各processは子孫process containment、active process 8件、memory 1 GiB、stdout／stderr各1 MiB、明示timeout、一時tree最大10,000 entry／1 GiBの内側で実行します。API keyやPython注入環境を継承せず、一時treeのreparse、hardlink、特殊file、path escapeを拒否し、保持する出力は単一handleからsize上限付きで再読込します。これらはkernel sandboxではありません。WebUI／APIのproduction経路では下記の直接path引数を使わず、operatorがraw SHA-256をpinしたmanifestからjob-private UPX／7zz／innounp snapshotを作る`analysis_job_runner.py`を使用します。request JSON、`PATH`探索、起動時downloadからtoolを指定できません。DIECはproduction契約では無効です。

```powershell
$Python = 'C:\Tools\Python313\python.exe'
$SevenZipNSIS = 'C:\Tools\7z-nsis\7z.exe'
$UPX = 'C:\Tools\upx\upx.exe'
$InnoUnp = 'C:\Tools\innounp\innounp.exe'
$DiE = 'C:\Tools\DetectItEasy\diec.exe'

& $Python .\unpackers\static_unpacker.py `
  --input C:\analysis\sample.quarantine.bin `
  --output C:\analysis\unpack.json `
  --artifact-zip C:\analysis\recovered-artifacts.zip `
  --upx $UPX `
  --sevenzip $SevenZipNSIS `
  --innounp $InnoUnp `
  --archive-password infected `
  --diec $DiE
```

この例の`--upx`、`--sevenzip`、`--innounp`、`--diec`は、隔離した解析者向けdirect CLIでだけ使用するpath引数です。WebUI／APIのproduction経路では使わず、前述のoperator manifestとSHA-256 pinを使用してください。`--artifact-zip`を指定した場合だけ、復元byteを書き出します。archiveは解析password `infected`を使ってAESで暗号化します。Gitへ追加しないでください。`--force-container-probe`は、レビュー済みinventory hintがある場合だけ使用します。このoptionは入力を実行せず、設定済み7-Zip binaryにPE/containerのparseを要求します。archive passwordを公開reportへコピーすることはありません。

report には hash、size、format、変換、信頼度、検体を実行していないこと、network 接続を行っていないことを記録します。

NSIS native 定数解析には Python package `capstone` が必要です。register/immediate 演算の線形な伝播だけを行い、memory、call、branch、検体を emulate しません。

managed protectorだけを確認する場合は次を使用します。既定出力はproxy件数とresource inventoryだけで、完全なtoken対応表は `--include-records` を明示した場合だけ含めます。

```powershell
& $Python .\unpackers\managed_proxy_deobfuscator.py `
  C:\analysis\managed-payload.bin `
  --output C:\analysis\managed-protector.json
```

入力、CLR、CILを実行せず、resource数64 MiB、入力512 MiB、proxy record 16,384件の上限を適用します。暗号化assemblyのsample固有鍵は自動推測せず、`limitations` と次の静的解析対象へ残します。

## 再帰的 family pipeline

family 全体を offline で解析する場合は、NSIS 対応 binary を使用します。収集日を directory 階層に混ぜず、private sample と隔離出力でも family/version の深さを揃えます。

```powershell
& $Python .\analysis-framework\common\analyze_stealer_set.py `
  --manifest C:\malware-lab\samples\remcosrat\<version-key>\manifest.json `
  --output C:\malware-lab\work\remcosrat\<version-key> `
  --definitions .\analysis-framework\definitions `
  --upx $UPX `
  --sevenzip $SevenZipNSIS `
  --diec $DiE
```

pipeline は復元 layer を最大 2 generation まで再帰的に検査し、復元 byte は暗号化したローカル解析 archive にだけ保存します。公開 case は `analysis-results/malware/remcosrat/versions/<version-key>/cases/<sha256>/` に保存し、収集元と収集日は `analysis-results/collections/<collection-id>/manifest.json` の membership として管理します。

## Status の解釈

`artifacts_recovered` は inner layer を 1 つ以上再構築できたことを意味します。最終 malware payload の unpack 完了を意味しません。terminal executable または script が構造的に有効で、追加の packing/protection layer を示す根拠がない場合だけ、case を完全に unpack 済みとします。

report では次の blocker class を使用します。

- `unsupported_static_transform`: decoder が未実装です。
- `native_control_flow_obfuscation`: 検証済み変換後も native loader が残っており、確実に継続するには実行または emulation が必要です。
- `runtime_derived_key`: key が machine state、timing、remote content に依存します。
- `missing_external_payload`: delivery layer が、提出 archive に存在しない content を参照しています。
- `encrypted_container`: 必要な password が不明です。
- `corrupt_or_truncated`: 宣言された境界または header を検証できません。
- `not_packed`: 高 entropy または難読化はありますが、除去できる独立した packer layer がありません。

## 失敗時の確認

1. outer archive が引き続き AES で暗号化され、想定 intake password で読めることを確認します。
2. NSIS 対応 7-Zip build を使用します。標準 7-Zip は、decompile 済み `[NSIS].nsi` control flow を生成せずに file だけを抽出する場合があります。
3. 空の `recovered` list を最終結果とする前に、`inventory`、`retained_members`、`split_reassembly`、`nsis_script_recovery` を確認します。
4. decoder の offset、size、key、source offset、出力 SHA-256、magic を report と比較します。範囲外または曖昧な変換は拒否します。
5. 復元したすべての layer を再帰的に解析します。有効な PE 自体が pack されている場合があります。
6. DiE/entropy の finding は hint として扱います。それだけでは packing の証明になりません。
7. 残った stage が control flow を難読化した native loader なら、blocker を記録し、完全 unpack 済みと暗黙に分類しません。

## 検証と API 文書

```powershell
& $Python -m pytest .\unpackers\tests -q
& $Python -m pydoc unpackers.static_unpacker
& $Python -m pydoc unpackers.go_embedded_pe
& $Python -m pydoc unpackers.opaque_native_entry
& $Python -m pydoc unpackers.javascript_obfuscator
& $Python -m pydoc unpackers.javascript_dropper_unpacker
& $Python -m pydoc unpackers.javascript_env_assembly
& $Python -m pydoc unpackers.managed_win32_rmp_loader
& $Python -m pydoc unpackers.javascript_reverse_base64
& $Python -m pydoc unpackers.batch_powershell_polyglot
& $Python -m pydoc unpackers.managed_handoff_image
& $Python -m pydoc unpackers.native_kmta_loader
& $Python -m pydoc unpackers.nsis_unpacker
& $Python -m pydoc unpackers.electron_nsis_unpacker
& $Python -m pydoc unpackers.inno_sideload_bundle
& $Python -m pydoc collection_followup_planner
```

HTML API文書はrepository root、`analysis-framework`、`analysis-framework/common`を `PYTHONPATH` に設定し、`docs/pydoc` で `python -m pydoc -w collection_followup_planner unpackers.opaque_native_entry unpackers.electron_nsis_unpacker unpackers.inno_sideload_bundle` を実行して再生成します。

unit test は、上限付き decode、malformed input、正確な hash/size、GDPF PDFのsize・overlay境界・magic、LZX CABのchecksum・window・volume・path・size・決定的順序、JavaScript rotation、逆順・separator付きBase64、UTF-16 normalization、numeric array と Unicode environment の復元、metadata拘束polyglotのcustom nibbleとAES-CBC／PKCS7／GZip、HOI1の完全消費・fixup境界・文字列定数、x64 export参照に拘束したKMTA復元とpadding／arch／PE extent拒否、分割 CMD Base64 の再構築、.NET bitmap 復元、AutoIt layer、split reconstruction、NSIS word decode、静的 XOR loop 認識、synthetic NSIS の end-to-end 復元を検証します。

## PureHVNC と CHRD/Donut の復元

- `purehvnc_unpacker.py` は、観測済みの first-byte/index-XOR envelope の内側から、sparse stride-four storage を含む構造的に有効な PE を検索します。
- `donut_unpacker.py` は、レビュー済みの modern `0x290` layout と legacy `0x23c` layout、Chaskey CTR、非圧縮 module、任意の aPLib 復元に対応します。
- `chrd_donut_unpacker.py` は、WAV、numeric segment、outer transform、Donut、managed TripleDES/GZip resource loader、terminal PE の順に、レビュー済み CHRD resource carrier を再構築します。

CHRD integration fixture は、実行も network 接続も行わずに terminal SHA-256 `c1a2b48d4f639b46cf6cde8322666f0991531ef32ffe571140418ae40342ffe8` を復元しました。生成 binary は隔離/output path に保存し、commit してはいけません。

## APT-C-60 / SpyGlace の復元

- `apt_c60_delivery.py` は LNK string と厳密な Base64/TAR carrier を安全に検査し、明示された `copy /b` fragment 連結だけを再現します。
- `spyglace_unpacker.py` は literal PE data と、レビュー済みの 2 種類の repeating XOR envelope を認識し、PE 構造を検証して静的 role を割り当てます。
- どちらの module も LNK、JavaScript、Git、script、loader、復元 PE を起動しません。

command の順序と失敗時の確認は `docs/APT-C60-2026-WORKFLOW.md` を参照してください。

## 現行 Donut、container、大容量 file への対応

- `donut_unpacker.py` は、レビュー済みの modern/legacy layout に加えて、現行の `0x240` と `0x230` array layout に対応します。call-over-instance prologue、API 数、DLL basename list、復号済み PE 範囲、出力 hash を検証します。
- `donut_wrapper_unpacker.py` は、decode 後の `SystemRoot`、`System32\conhost.exe`、quoted argument template を検証してから、レビュー済み 32 byte XOR wrapper を復元します。
- `container_recovery.py` は、連結 XZ stream、上限付き XML plist trailer、Mach-O FAT slice、拡張された PE certificate gap を処理します。
- `static_unpacker.py` は Apple disk image と複数 member を持つ malware 所有 archive を再帰 layer として扱います。64 MiB を超える file には、決定的な上限付き entropy sampling と marker probe を使用します。

すべての変換は構造を検証し、memory 内または隔離した一時 path で行います。復元 PE は再帰的に解析しますが、起動しません。

## Electron ASAR と Java/Mach-O の境界

- `asar_unpacker.py` は、memory 内 member を返す前に Chromium ASAR pickle の境界、member offset、integrity metadata、path traversal を防ぐ name、総出力上限を検証します。
- `electron_nsis_unpacker.py` は 7-Zip を parser としてだけ使用し、入れ子の Electron archive を特定して `resources/app.asar` を復元します。NSIS、Electron、JavaScript、復元 payload は起動しません。
- `inno_sideload_bundle.py` は Inno Setup memberの相対path、launcher import、同名DLL配置を上限付きで照合し、launcher／side-load DLL候補を決定的に記録します。installer、launcher、DLLは起動しません。
- `static_unpacker.py` は両経路を再帰的に適用し、JavaScript を評価せず、レビュー済みの plain JavaScript string array rotation を難読化解除できます。
- Java class file と universal Mach-O は `CAFEBABE` magic を共有します。format detector は、妥当で上限付きの Mach-O architecture table を要求し、それ以外を `java-class` と分類します。

関連 test は `test_asar_unpacker.py`、`test_electron_nsis_unpacker.py`、`test_javascript_plain_array.py`、`test_static_unpacker.py` の Java/Mach-O regression です。

## 宣言型byte変換プロファイル

`profiled_transform.py` は `profiles/byte_transforms.json` を読み、入力形式と任意のファイルsuffixに合う変換だけを適用します。新しいローダーの回転量やXOR鍵をPythonへ直接追加せず、JSONのoperation列と構造validatorで定義できます。`rotated_xor_donut.py` は旧CLIと関数APIを維持する薄い互換ラッパーです。

プロファイルから実行できるのは反転、左右ローテート、単一byte XOR、繰り返し鍵XOR、上限付きsliceだけです。任意コード、式評価、外部コマンド、ネットワーク処理は呼び出せません。詳しい追加手順は [拡張可能な静的解析プロファイル](../analysis-framework/docs/EXTENSIBLE-STATIC-PROFILES.md) を参照してください。

## MSI／OLE／CABとdetached IDAT

`static_unpacker.py`はMSIをOLEとして扱い、stream数、単体サイズ、合計サイズの上限内でCAB、PE、ZIP、script、設定候補を復元する。CABはまず純粋Pythonの解析器を使い、LZXなどの非対応圧縮方式や解析失敗で復元できない場合だけ、利用者が`--sevenzip`で明示したローカル実行ファイルへフォールバックする。MSI自体や内包ファイルは実行しない。

PNG signatureやIHDRを持たず、CRC-validな`IDAT`が2個以上連続して`IEND`で終わるデータはdetached IDATとして記録する。結合データがzlibとして正常終端した場合だけ復元層を出力する。zlibでない場合は暗号化・独自変換候補として境界、チャンク数、SHA-256、エントロピーだけを保存し、推測したバイト列は出力しない。

多数の正規ファイルを含むCABでは、設定名を参照するPEとdetached IDATを後段解析へ優先する。優先度はファミリー確定ではなく、層数上限で重要証跡が落ちることを防ぐための順序である。

archive内の棚卸し上限は512、再帰解析で採用する静的層上限は64であり、別々に適用する。棚卸し件数が採用層上限を超えてもコンテナ全体を拒否せず、優先順位に従って境界内の層を採用する。

MSIの標準テーブルを相関する場合は、読み取り専用の`msi_static_inventory.py`を使用する。

```powershell
python unpackers/msi_static_inventory.py `
  --input C:\analysis\sample.msi `
  --output C:\analysis\msi-inventory.json `
  --max-rows 4096
```

入力サイズは既定で256MiBを上限とし、SHA-256はストリーム単位で計算する。出力には絶対パスを残さず、入力ファイル名、`File`、`CustomAction`、`InstallExecuteSequence`、`Media`、カスタムアクションのsource IDから実ファイル名への対応を含む。Windows Installerのインストール処理は呼び出さない。

## コード参照に基づくGo・ARX20包装の静的復元

`go_embedded_pe.py`は、x64 PEのGo関数表、`main.main`のコピー引数、復号関数の5段の数学処理を照合する。コピー先頭の短いprefix、参照元、長さ、鍵は各入力の命令列から取得する。復号結果のPE境界と実行可能section内のentryを検証してから、通常の静的layer解析へ渡す。Go本体、復元PE、CPU命令を実行しない。

`arx20_chunk_unpacker.py`と`arx20_static_route.py`は、indexとchunkの呼出し、状態wordの配置、20-roundの算術演算・feedforward・counterをレビュー済みcompiler-shapeで照合する。参照RVA・sigma・鍵・nonceは各入力から取得し、検体SHAだけで復号器を選択しない。未知compiler-shape、演算改変、範囲外・重複chunk、過大宣言、候補数超過を拒否する。巨大overlayを探索・復号範囲へ含めない。

ARX20の入力上限は64MiB、全候補合計の暗号処理量は1MiB、呼出し時間は8秒。時間・処理量の上限に達した場合は部分的な成功結果を返さず、通常の非一致と区別して記録する。Donut候補はinstance、module宣言長、非圧縮条件、最終PEを検証し、未対応の圧縮を無制限に伸長しない。Donut候補は後段の既存静的parserへ渡す。

どちらも包装の復元と親子hashの証拠を生成する機能である。復元成功だけでファミリー、C2、終端解析完了、稼働状態へ昇格させない。これらは後段の設定抽出と関数参照の確認により個別に判断する。

無害なPEと非実行の命令fixtureによる回帰テストは、`test_go_embedded_pe.py`、`test_arx20_chunk_unpacker.py`、`test_arx20_static_route.py`を参照する。実検体binary・復号済みpayload・生の鍵はテストfixtureへ含めない。

## Environment分割型JScript loader

`javascript_env_assembly.py`は、UTF-16LE JScript内の区切り文字付きBase64を、JavaScriptやPowerShellを実行せずに復元する。検体ごとの変数名やhashには依存せず、同一変数のliteral連結と区切り除去、`HKCU\Environment`への上限付き分割、PowerShellの`Assembly.Load(FromBase64String(...))`、隠し`Win32_Process`起動、復元PE構造をすべて確認する。literal境界で分割されたUTF-16 surrogate pairも、元のcode unit順を維持して再構成する。

入力は16 MiB、復元文字列は32 MiB、復元assemblyは64 MiB、literalは256個、Environment chunkは512個を上限とする。候補が複数ある場合、Base64がcanonicalでない場合、PEでない場合、または静的な実行契約を一意に確認できない場合はartifactを出力しない。

一般のmanaged loaderでは、埋め込まれた引数のhash・長さ・Base64形状だけを記録し、復号方法を推測しない。`managed_win32_rmp_loader.py`は、5個のMethodDef body hash、単一embedded resourceのhash／size、resource変換、password位置／hashがすべて確認済みprofileへ一致する場合だけ、AES-CBC／PKCS7で19引数を復号する。入力assemblyは16 MiB、resourceは1 MiB、各平文引数は4 KiBを上限とし、生password、生key、URL以外の平文引数はreportへ出さない。URLのqueryはtoken露出を避けるため候補から除外し、存在だけを記録する。公開した平文引数のindexは機械可読に記録する。

profile一致時もURLは`payload_acquisition_candidate`として記録する。このURLはloaderへ渡された外部payload取得候補であり、PureLogsなどのfamily帰属、C2確認、URL先の生存、終端payload到達を証明しない。自動取得や外部通信は行わず、profile不一致、19引数schema不一致、URLや保存先の形状不一致、候補の曖昧性は安全側に拒否する。

## OMLX仮想化resourceの終端復元

`managed_omlx_tripledes.py`は、OMLXの176-way dispatcher handlerから静的に証明したopcode subsetだけを有界な定数データフローとして解析する。`GetManifestResourceStream`のcallerが指定するresource名、直接Eaz keyed-word transformのcanonical core、未参照の第2引数、partial-word処理、復号後の完全な長さ付きUTF-16LE tableをすべて照合する。initializerの124 fieldから証明したselectorはkey、IV、ResourceSet entry名の境界と一致する場合だけ受理する。

続いて、同じ親PEから復元したEaz child内の単一ByteArray entryにTripleDES-CBC、PKCS#7、4-byte展開長付き単一GZip memberを適用し、展開長、GZip終端、trailing data、PE境界、CLR metadataを再検証する。生keyと生IVはreportへ出力せず、長さとSHA-256だけを記録する。未知opcode、候補の複数成立、resource名の不一致、不正な暗号・圧縮・PE構造はartifactを出力しない。この復元成功は保護recipeと親子層の証拠であり、それだけでfamily、C2、終端設定を確定しない。
