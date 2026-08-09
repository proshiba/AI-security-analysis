# RemusStealer process dump静的一括解析

## 目的

公開sandboxから取得したfull process dumpをローカルで実行せずに走査し、mapped PE、RemusStealerの暗号化設定、静的C2 endpoint、C2プロトコル判定profileを同じ入力から復元します。標準入口は `common/analyze_remus_process_dump.py` です。

静的設定の復号成功は、C2の現在の稼働確認ではありません。公開結果では `confirmed_static_config` とライブ確認結果を分離してください。

## 推奨する一括実行

次の例は `analysis-framework/` をcurrent directoryとします。入力dumpと復元PEはGit管理外の対象別private directoryへ置きます。出力directoryは新規pathでなければなりません。

```powershell
py -3.13 .\common\analyze_remus_process_dump.py `
  --input C:\private\remus\process-memory.dmp `
  --output-dir C:\private\remus\recovered `
  --parent-sha256 <元検体の64桁SHA-256>
```

一括CLIは次の順で処理します。

1. dump内の全 `MZ` 候補を上限付きで走査する。
2. section境界を検証し、memory-only sectionを含むPEを再構築する。
3. Remus固有のChaCha20 state、暗号化endpoint slot、selector、tag候補を抽出する。
4. 秘密値を除いた受動C2 profileを生成する。
5. 復元PEとsanitize済み `analysis-report.json` を排他的に保存する。

## 個別CLI

切り分けが必要な場合だけ個別CLIを使います。

```powershell
py -3.13 .\common\recover_process_dump_pe.py `
  --input C:\private\remus\process-memory.dmp `
  --output-dir C:\private\remus\pe-recovery `
  --mapped-mode expanded_memory_sections

py -3.13 .\common\remus_memory_config.py `
  --input C:\private\remus\pe-recovery\pe_0001_<sha-prefix>.bin `
  --layout file `
  --output C:\private\remus\remus-memory-config.json

py -3.13 .\common\remus_c2_profile.py `
  --input C:\private\remus\reviewed-profile-input.json `
  --output C:\private\remus\remus-c2-profile.json
```

`remus_c2_profile.py` はprofileを生成するだけで、ネットワーク接続を行いません。能動profileは、選択endpoint、`recovered`／`confirmed`／明示review済みのtag、review済み `exp`、review済みHTTP Host、単一のglobal pinned IP、親検体SHA-256、process dump SHA-256、復元PE SHA-256がすべて揃い、さらに各値を同一検体・同一flowへ結合したfield-level証拠manifestを検証できた場合だけ `ready` になります。単なる `candidate` tagは受動profileへ保持しますが、`tag_unreviewed` で能動profileを遮断します。他検体の値は補完しません。

一括CLIでtagを人手レビューした場合だけ `--reviewed-tag <32桁hex>` を指定します。静的な32桁文字列候補を見つけただけでは指定しません。

field-level証拠manifestはrepository内のstrict UTF-8 JSONとして作成し、次の値を固定します。

- 親検体、process dump、復元PEのSHA-256
- tag、`exp`、HTTP Host、単一pinned IP
- 選択slotを含むendpoint object
- 全fieldの親検体SHA-256と、通信fieldで共通するflow証拠SHA-256

manifestは64 KiB以下の単一link通常fileに限定し、profileへrepository相対path、manifest SHA-256、canonical JSON Pointer集合を保持します。一括CLIでは `--evidence-manifest-source`、`--evidence-manifest-sha256`、`--evidence-review-id`、`--repository-root` を同時に指定します。profile生成時、監視計画への適用時、実probe直前に同じvalidatorで再検証されます。

manifestが存在しない、空、過大、SHA-256不一致、pointer不一致、別検体・別flowの値を含む、reparse point／hardlinkである、読み取り中に差し替えられた、profile入力または出力自身を参照する場合はfail-closedで遮断します。

### 固定review registryとflow artifact

manifestだけでは能動profileを許可しません。固定path `analysis-framework/common/remus_active_profile_review_registry.json` のreview registryに、`approved` 状態の `review_id` が登録されている必要があります。登録項目はmanifestとflow artifactのrepository相対path／SHA-256、canonical JSON Pointer集合、親検体SHA-256、run ID、dump SHA-256、復元PE SHA-256です。一括CLIではmanifest指定に加えて `--evidence-review-id` を必ず指定します。

flow artifactは同じrunの親検体、process dump、復元PE、tag、`exp`、HTTP Host、pinned IP、endpointを結合するstrict UTF-8 JSONです。256 KiB以下の単一link通常fileだけを許可します。review registry自体も64 KiB以下とし、重複key、`NaN`／`Infinity`、reparse point、hardlink、読み取り中の差し替えを拒否します。

text JSONのdigestはstrict UTF-8 byte列のCRLFをLFへ置換したcanonical LFで計算します。LF／CRLF以外の空白、key順、値が変化すればdigestも変化します。検体、process dump、復元PEなどbinary／raw artifactのSHA-256は正規化せず、元byte列へ対して計算します。

監視計画はC2 protocol profile registryとRemus review registryのsource／SHA-256を固定します。計画検証時と送信直前にprofile registry、review registry、manifest、flow artifactを再読込し、検体集合もprofileと完全一致する場合だけ送信経路へ進みます。現在の根拠不足profileは能動profileとして適用せず、inventoryへ `remus_review_evidence_unavailable` として記録します。

### 能動probeの上限と判定

Remus能動probeを許可できる場合でも、1 endpointにつき最大2 request、全request timeoutは3.0秒、requestは4,096 byte以下、responseは8,192 byte以下、接続先はcanonicalな単一global IPへ限定します。値、型、IP数、registry pin、artifact pinのいずれかが変化した場合、application dataは0 byteのまま遮断します。

task応答の `type` はboolを除く整数 `0..5` だけを候補として受理します。ただし `name` と `data` の実protocol型はまだ静的に確定できていないため、3 keyが揃っても `remus_task_schema_unverified` とし、C2 confirmedを禁止してoperational confidenceを0にします。access token、task名、task data、synthetic HWIDは公開しません。

## 完了状態とexit code

| `analysis-report.json` のstatus | exit code | 意味 |
|---|---:|---|
| `complete` | 0 | PE、設定、能動C2 profileまで完了 |
| `error` | 2 | PE／設定の一意復元またはprofile生成処理が失敗 |
| `partial` | 3 | PEと設定は復元済みだが、能動C2 profileは根拠不足でblocked |

自動処理はexit code 3を成功完了として扱わず、`active_profile_generation.blocked_reasons` を後続レビューへ渡してください。

## 安全境界と公開禁止値

- 検体の実行、CPUエミュレーション、外部通信を行いません。
- 入力size、PE候補数、候補size、合計出力size、config slot数に上限があります。
- reparse point、hardlink入力、既存出力、入力と出力の内包関係を拒否します。証拠manifestも同じidentity検証と64 KiBのbounded readを通します。
- 復元したPE、process dump、raw configなどの非公開byte列はGitへ追加しません。
- runtime access tokenの値、ChaCha20 key、nonceはreportへ出力しません。存在、位置、長さ、SHA-256だけを記録します。
- endpoint復号結果は静的C2設定であり、ライブC2確認や所有確認として扱いません。
- private成果物は対象ごとにpassword `infected` のWinZip AES-256 ZIPへ分離し、[解析データストア手順](ANALYSIS-DATASTORE.md)に従って保管します。

## 失敗時の確認

- `remus_config_not_found`: 復元PEが終端payloadか、dump取得時刻が設定復号後かを確認します。
- `remus_config_ambiguous`: 同一dumpに複数process imageが混在していないか確認し、process単位のdumpへ絞ります。
- `active_profile_generation.status=blocked`: `blocked_reasons` の不足根拠を同一検体から補い、field-level manifestへ同一flowとして結合します。他検体のtag、`exp`、Host、IPを流用しません。
- selector未復元: file/mapped layoutの指定と、復元PEのsection配置を確認します。
