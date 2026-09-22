# VenomRAT・ValleyRAT候補の未完了ケース静的監査

監査日: 2026-09-22。指定された2件の既存成果物を再評価した。検体実行、C2・配布先への接続、追加payload取得は行っていない。現在参照できるGhidraプロジェクトにも両検体は開かれておらず、ローカルの私有解析領域で元バイナリを発見できなかった。このため、新規の逆コンパイル結果を得たものとは扱わない。以下の「最近」は検体提供元の初回観測日を指し、日本国内の感染を立証するものではない。

| ケース | 既存静的証拠の到達点 | 未解決の中心 |
|---|---|---|
| VenomRAT `9c8969b2fc30c395e31a4443cc691c889b309f906e69c2f98cdd92adb812b456` | 構造検証済み.NETクライアント、HMAC検証済み設定 | 実C2、動的設定の現在値、実行時の分岐 |
| ValleyRAT報告 `658fc8b2caf56d7572f065bdc7bcf248f1ba3e96901ba6ed3eee4291e524d46e` | PE、import・文字列、選定関数のGhidra静的記録 | 内部ファミリー確認、終端機能、設定・C2、命令経路 |

## VenomRAT検体：`9c8969…`

提供元初回観測は2026-09-06。既存の[メタデータ](../../../malware/venomrat/versions/unknown/cases/9c8969b2fc30c395e31a4443cc691c889b309f906e69c2f98cdd92adb812b456/metadata.json)は、提供元ラベルとは別に、静的handlerによるファミリー確認を記録している。[handler結果](../../../malware/venomrat/versions/unknown/cases/9c8969b2fc30c395e31a4443cc691c889b309f906e69c2f98cdd92adb812b456/handlers/venomrat-5cc651e5d43fb84e.json)はCLR構造とVenom固有の難読化設定field群を照合し、HMAC-SHA256検証後に設定を復元したと記録する。回収された版表示は `Venom RAT + HVNC + Stealer + Grabber v6.0.3`、groupは `Default`。ただし正式な版キーは既存メタデータで `unknown` のままであり、この表示を検体系列全体の版として一般化しない。

設定にある動的設定resolverは `hxxps://pastebin[.]com/raw/LwwcrLg4`、証明書SHA-256 pinは `4370b606ee51b67ab75611600406eb74762f5c134309358d042d696d789c5e22`。resolverはC2本体ではなく、接続・内容確認もしていない。handlerの `endpoints` は空であり、[C2評価](../../../malware/venomrat/versions/unknown/cases/9c8969b2fc30c395e31a4443cc691c889b309f906e69c2f98cdd92adb812b456/c2-analysis.json)も未解決である。公開用IOC一覧が空のままなのは、動的設定URLやpinを確定C2へ昇格していないためと解釈できる。設定の `install=false` と `anti_analysis=false` は条件分岐に関係し得るが、当該分岐が実際にどう評価されたかは未確認。

[関数単位の既存静的記録](../../../malware/venomrat/versions/unknown/cases/9c8969b2fc30c395e31a4443cc691c889b309f906e69c2f98cdd92adb812b456/static-logic.json)には、264 managedメソッドのinventoryと32代表メソッドのCIL解析がある。`Client.Program.Main` (`0x06000030`) の呼出先にはmutex作成、設定初期化、registry初期化、`Install`、anti-analysis、`Run` が含まれる。これは実装された経路候補であり、設定値や環境条件を無視して「永続化が実行された」とは言えない。`Client.Install.NormalStartup.Install` (`0x0600005d`) にはregistry更新、ファイル操作、`Process.Start`、既存プロセスの列挙・終了の参照があるが、固定コマンドラインおよび実際の起動条件は復元されていない。

通信側では `Client.Connection.ClientSocket.InitializeClient` (`0x06000050`) に `WebClient.DownloadString`、DNS解決、socket接続、`SslStream.AuthenticateAsClient`、`SendInfo` の参照がある。`ReadServertData` (`0x06000054`) はstream読取りと長さ処理、`KeepAlivePacket` (`0x06000056`) は送信とactive-window取得、`Client.Helper.IdSender.SendInfo` (`0x0600007d`) は端末・OS・ユーザー・CPU/GPU・RAM・プロセスなどの情報取得を参照する。`Client.Keylogger.SendLog` (`0x06000014`) はローカルログの読取り・送信・削除の参照、`ClientSocket.Invoke` (`0x06000059`) は展開済みassemblyを `AppDomain.Load` とreflectionで呼び出し得る構造を示す。これらはコード上の機能を示すが、送信済みデータ、受信命令、plugin実行を観測した証拠ではない。既存CIL記録には生の分岐条件・packet field値が保存されず、正確な通信frameや命令IDはまだ確定できない。

次の静的作業は、元バイナリを再取得可能な私有保管から確認したうえで、`InitializeClient` のresolver取得後のデータフロー、証明書照合、`SendInfo`/`KeepAlivePacket` のMessagePack field、`Invoke` の命令分岐をCIL命令単位で追うこと。通信先への接続なしでも、少なくとも固定設定と分岐条件をより厳密に確定できる。

## ValleyRAT報告: `658fc8…`

提供元初回観測は2026-09-13。元ファイル名は中国語の言語パック導入を促すものだが、それ自体は日本国内感染の根拠ではない。[メタデータ](../../../malware/valleyrat/versions/unknown/cases/658fc8b2caf56d7572f065bdc7bcf248f1ba3e96901ba6ed3eee4291e524d46e/metadata.json)と[分類](../../../malware/valleyrat/versions/unknown/cases/658fc8b2caf56d7572f065bdc7bcf248f1ba3e96901ba6ed3eee4291e524d46e/classification.json)は、ValleyRATをMalwareBazaar由来の報告ラベルとして保持し、内部の静的ファミリー帰属を未確認としている。handler成功0件、[route設定候補](../../../malware/valleyrat/versions/unknown/cases/658fc8b2caf56d7572f065bdc7bcf248f1ba3e96901ba6ed3eee4291e524d46e/route-config-candidates.json)0件、[C2評価](../../../malware/valleyrat/versions/unknown/cases/658fc8b2caf56d7572f065bdc7bcf248f1ba3e96901ba6ed3eee4291e524d46e/c2-analysis.json)のendpointも空。名称だけでValleyRAT固有の通信・機能を補完してはならない。

[汎用静的トリアージ](../../../malware/valleyrat/versions/unknown/cases/658fc8b2caf56d7572f065bdc7bcf248f1ba3e96901ba6ed3eee4291e524d46e/generic-triage.json)では `CreateProcessW`、registry操作、サービス制御、`IsDebuggerPresent` などのimportを確認する。文字列には対象プロセスの終了、Defender policy変更、Telegram、`firefox_pass.exe` が見える。これらはコード上の機能仮説を絞る材料ではあるが、入口からの到達性、変更先の実値、生成プロセス、資格情報取得、後段payloadの存在は未立証。列挙されたURLの多くは署名証明書のCA/CRL/OCSP由来で、C2に転用できない。[静的レイヤー](../../../malware/valleyrat/versions/unknown/cases/658fc8b2caf56d7572f065bdc7bcf248f1ba3e96901ba6ed3eee4291e524d46e/static-layers.json)は復元子要素0件、構造分類 `not_packed` と記録する一方、[正規化解析](../../../malware/valleyrat/versions/unknown/cases/658fc8b2caf56d7572f065bdc7bcf248f1ba3e96901ba6ed3eee4291e524d46e/analysis.json)は `packing_suspected=true`。両判定は矛盾するため「packer内の終端payloadがある」と断定せず、`.rdata` の高entropyなどの原因を再確認する。

[Ghidra由来の既存記録](../../../malware/valleyrat/versions/unknown/cases/658fc8b2caf56d7572f065bdc7bcf248f1ba3e96901ba6ed3eee4291e524d46e/static-logic.json)は1,339関数のinventoryを持つが、個別解析は32関数で、そのうち1件は逆コンパイル制約付きである。特に `_guard_dispatch_icall` (`0x140065ab0`) を `command_dispatch_or_handler`、entryからの辺を `startup→dispatch` と記載する既存要約は意味付けが強すぎる。このシンボルはMSVC Control Flow Guardの間接呼出し補助関数を示し、C2命令分配の根拠ではない。元記録でもAPI参照は空で、jumptable回復失敗を記している。したがって「受信命令を分配する」能力は現時点で未確認とする。

次の静的作業は、検体を再入手して署名・PEセクション・resource/overlayを再検証し、Defender policyやプロセス終了文字列の参照元を入口から追跡すること。実際のValleyRAT系列の固有設定構造・通信関数が確認できた場合に限り、ファミリー、C2、挙動を昇格する。元検体のない現段階では、既存の外部ラベルと汎用APIだけで判定を確定しない。

## 日本国内事例との結び付き

両ケースの既存成果物には、日本国内の被害組織、配布メール、侵入経路、観測された感染ホストとの検体hash照合がない。したがって、これらを日本国内の最近の感染事例そのものとして扱わない。国内事例の優先分析に使う場合は、国内発生報告の一次資料と配布物・後段・hashの連鎖を別途照合し、この静的ケースへ明示的に紐づける必要がある。
