# 宣言型byte変換の共有予算と設定検証

## 目的

複数の変換プロファイルを連続適用するとき、各プロファイルの入力上限だけでは合計処理量を制限できません。`unpackers/profiled_transform.py`は全プロファイルで処理量、保持量、経過時間の予算を共有します。単一プロファイルの`recover_transform_profile`も同じ予算を使い、構造検証の前後と成果物の保持前に確認します。検体、復元バイナリ、スクリプト、CPU命令、CLR、CILは実行しません。外部通信やコード評価も行いません。

## 上限

| 対象 | 上限 | 超過時 |
|---|---:|---|
| 設定JSON | 1 MiB | 本文読込前に拒否 |
| プロファイル | 128件 | 設定を拒否 |
| 一つの操作列 | 16操作 | 設定または直接APIを拒否 |
| 変換入力 | 64 MiB | 適用対象外または直接APIを拒否 |
| 全操作の入力とDonutヘッダー観測の予約byte数合計 | 256 MiB | 以後の適用候補を未評価として記録 |
| 全成果物の保持量 | 128 MiB | 当該成果物を保持しない |
| 操作境界で確認する経過時間 | 10秒 | 以後の適用候補を未評価として記録 |
| Donut検証stride | 重複なし16件 | 設定を拒否 |
| Donutヘッダーprobe | 一つのvalidatorにつき4,096件 | 当該検証をpartialとして記録 |
| Donutヘッダー候補 | 一つのvalidatorにつき256件 | 当該検証をpartialとして記録 |
| 公開するDonut候補offset | 最初に観測した16件 | offset一覧の省略を明示 |
| 通常ZIPの構造検証member | 4,096件 | 構造候補として採用しない |

APIの`max_work_bytes`、`max_artifact_bytes`、`max_elapsed_seconds`は上限を引き下げるために使用できます。上限の無効化、増量、NaN、Infinity、真偽値の指定は拒否します。

静的アンパッカーからの呼出しでは、宣言型変換の保持量をcallerの`max_archive_total_size`以下へ制限します。この制約は変換部分の保持量に対するもので、先行する別復元器を含むpipeline全体の総量検証は静的レイヤーrunnerが引き続き担当します。

処理量は、各操作を開始する前の入力長と、Donut validatorのstrideごとの入力scan長、5-byteのヘッダーprobe、最大42-byteの既知prologue観測窓を、処理前に予約して加算します。`budget.operation_input_bytes`、`budget.validator_probe_bytes`、`budget.total_work_bytes`を分けて返します。PE、ZIP、magicの構造validatorはこのbyte計数へ追加せず、入口・終了後の時刻確認を行います。この値は演算回数、Pythonの全メモリ使用量、実際のコピー回数の厳密な計測値ではありません。時間は操作の前後、構造検証の境界、reportのhash作成後、成果物の保持前と複数profileの終了時に確認します。進行中のPython操作や依存parserを強制中断する機能ではなく、production runnerのprocess・memory・timeout制約を置き換えません。

## 設定の再現性

JSONの重複key、未知key、非有限定数、曖昧な型、重複形式・suffix・strideを拒否します。操作とvalidatorは許可リスト方式を維持します。ファイルは通常file、単一link、非reparse、容量、親directoryのidentityを検証し、単一handleから有界に読みます。読込前後のidentityとsizeを照合します。

cacheのkeyは検証した文書bytesです。mtimeとsizeが同じでも別内容へ変更された設定を旧cacheへ誤結合しません。返す設定は独立したcopyであり、呼出し元がdictを変更しても次の検体へ持ち越しません。これは非特権の敵対的processを隔離するkernel sandboxではありません。

## 結果の解釈

`partial_shared_budget_limit`は候補を一部復元できていても全候補を評価し終えていない状態です。`limit_reasons`、`profile_evaluation_complete=false`、個別の`shared_budget_limit`／`skipped_shared_budget_limit`を記録します。先に構造検証した成果物は保持しますが、上限で保持できなかったものを取得済みと数えません。one-shot解析の未完了判定へ伝播します。

単一APIでも、validatorが期限を超えた場合、hash作成後に期限へ達した場合、または保持量を超える場合は成果物を返さず`partial_shared_budget_limit`とします。正常時のreportと成果物のtuple、および従来の回転XOR wrapperの成功名は維持します。従来wrapperの互換reportは既存の`xor_key`欄を維持するため、鍵値を除外した新しい`operations` projectionと同じ公開契約ではありません。

Donut validatorは宣言されたinstance長と有界な既知loader prologueのヘッダー外形だけを観測します。疎な入力からlane全体を作ったり、重なったcandidate本文を切り出してhashで重複排除したりしません。`candidate_bytes_materialized=false`、`instance_decrypted=false`、`runtime_code_executed=false`を記録します。Donutの復号・展開・回復アルゴリズムや`donut_unpacker.py`の本文回収器は変更しません。

`candidate_count`はpayloadの同一性を検証した件数ではなく、strideとE8位置ごとのヘッダー観測数です。`candidate_count_scope=header_observation_positions_not_unique_payloads`で区別します。候補offsetを16件へ省略してもscan自体が完了していれば`scan_complete=true`を維持し、`candidate_offsets_truncated=true`を併記します。一方、probe、候補数、共有作業量、時間の上限で観測が打ち切られた場合は`scan_complete=false`、`candidate_count_is_lower_bound=true`、固定の`limit_reasons`を返し、通常の陰性完了や全体成功に昇格させません。

暗号化instance内には偶然のE8が多数含まれるため、ヘッダーinventory固有の`donut_header_probe_limit`／`donut_header_candidate_limit`だけが原因なら、既に少なくとも一つのcall-over-instanceと既知prologueを観測できたbyte列を構造検証済み成果物として保持できます。この場合も単一report・全体reportはpartialのままで、候補件数は下限、後続profileは未評価です。既知外形を一つも観測できていない場合は成果物を返しません。時間、共有作業量、保持量の硬い上限超過が発生した当該profileの成果物は、観測済み外形があっても返しません。inventory partialを理由に硬い予算を緩める経路はありません。

公開reportの`operations`は`key`と`key_hex`を含めず、XOR鍵の長さ、SHA-256、`key_published=false`だけを返します。変換に必要な実値は検証済み内部設定だけに保持します。短い鍵、特に単一byte鍵のhashは総当たりで値を特定できるため、これは機密性の証明や秘密鍵の安全な公開方法ではありません。

入力に対してsliceの結果が空になる等の`transform_rejected`は当該プロファイルの不適合です。他のプロファイルの評価を停止しません。PE検証はparserのheader読込だけでなく、宣言したsectionとsecurity領域のfile境界・件数も確認します。復元成功はファミリー確定、終端payload到達、C2設定確認、C2稼働確認ではありません。

ZIP検証ではEOCD、central件数・サイズ、local header、同一member名、圧縮サイズ、CRC宣言値、data descriptor、member領域の重なりを展開せず照合します。ZIP64と複数diskは未対応として拒否します。`header_bounds_validated`はmember本文の復号・展開・CRC計算を意味しません。`member_content_read=false`と`content_crc_verified=false`を明示し、本文の完全性は後段の有界archive処理で別に検証します。

## 回帰試験

`unpackers/tests/test_profiled_transform_safety.py`は合成設定と無害なPE外形・Donutヘッダー外形だけを使い、設定破損、同size・mtimeの変更、cache汚染、共有処理量、保持量、仮想時計での時間超過、単一APIのdown-only予算、鍵値の非公開、重複E8の本文増幅回避、ヘッダー観測の打切り、疎なstride、PE範囲外参照、one-shotの未完了伝播を確認します。既存の変換・互換wrapper・静的レイヤー回帰試験も併せて実行します。

```powershell
& 'C:\Users\Administrator\Tools\Python313\python.exe' -B -m pytest -q unpackers/tests/test_profiled_transform.py unpackers/tests/test_profiled_transform_safety.py unpackers/tests/test_rotated_xor_donut.py
```
