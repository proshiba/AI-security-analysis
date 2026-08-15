# Vidar／AMOS経路差分プローブ

## 目的

[`stealer-route-c2.nse`](scripts/stealer-route-c2.nse)は、静的解析でレビュー済みのVidarおよびAMOSのHTTP経路を、陰性対照と比較します。TCP openだけを記録していた従来方式より識別力を高めますが、マルウェア固有の登録応答や暗号応答は確認しません。そのため一致時も`probable_c2=true`に限定し、`c2_confirmed=false`を維持します。

FormBookは終端URI、鍵、応答契約が未回収です。404やroot pageだけでは実C2と64個のdecoyを区別できないため、[`xloader-c2.nse`](scripts/xloader-c2.nse)の`transport-only`を継続します。`xloader.variant=formbook`を指定すると、`formbook_terminal_profile_required_tcp_open_only`を返します。

## 安全境界

- profile ID、同じ値のacknowledgement、`vidar`または`amos`のmode、対象と同じ数値IP pinが揃うまで、script固有のsocketを開きません。
- production profileはTCP 443だけを許可します。script内で名前解決せず、operatorが指定した数値IPへだけ接続します。
- Vidarは2回、AMOSは3回の`HEAD`要求に固定します。要求body、端末識別子、認証情報、cookie、収集dataは送信しません。
- redirect、応答body、task、payloadは追跡しません。公開結果にcampaign IDや生の応答headerを含めません。
- profileにないhost、path、User-Agentを引数で上書きできません。
- 許可済み監視対象だけに使用します。検体や復号payloadは実行しません。

## 判定条件

Vidarは、レビュー済みroot経路が`200`、`204`、`401`、`403`、`405`のいずれかで、固定陰性対照が`400`、`404`、`410`のいずれかの場合に限り、confidence 0.60のprobable判定とします。静的根拠は、検体`3bb64d86…13bc67c`から復元したdirect IPと完全一致User-Agentです。Telegram／Steamのdead-drop候補へは接続しません。

AMOSは、同一campaignの`/ledger/<id>`と`/ledger/live/<id>`の両方が上記の経路statusを返し、固定陰性対照が不存在statusを返す場合に限り、confidence 0.65のprobable判定とします。3検体から復元したsame-hostの経路対だけを許可します。

いずれも陰性対照との差がない場合はconfidence 0.15、接続前に失敗した場合は0.0です。HTTP status差は経路能力の証拠であり、C2 protocol確認、現在の運用主体、implant受理を意味しません。

## 実行方法

まず対象domainを組織の承認済み手段で数値IPへ解決し、そのIPをNmap targetと`stealer-route.expected-ip`の両方へ指定します。下記はplaceholderであり、そのまま実行できません。

```powershell
nmap -n -sT -Pn -p 443 --script .\analysis-framework\nmap\scripts\stealer-route-c2.nse `
  --script-args "stealer-route.mode=vidar,stealer-route.profile-id=vidar-3bb64d86-direct-route-v1,stealer-route.acknowledge-profile=vidar-3bb64d86-direct-route-v1,stealer-route.expected-ip=<approved-numeric-ip>" `
  <approved-numeric-ip>
```

AMOSのprofile IDは次の3件です。

- `amos-nvoaagent-ledger-route-v1`
- `amos-flwoagent-ledger-route-v1`
- `amos-northernvirginiapainting-ledger-route-v1`

modeを`amos`へ変更し、選択したprofile IDを`profile-id`と`acknowledge-profile`へ同値で指定します。argumentをshell historyへ残したくない場合は、権限制限した`--script-args-file`を使用してください。

## localhost検証

外部接続なしの標準検証は次のとおりです。

```powershell
py -3.13 -B .\analysis-framework\nmap\verify_nse.py `
  --nmap C:\Tools\Nmap\nmap.exe
py -3.13 -B -m pytest -q .\analysis-framework\tests\test_nmap_c2_scripts.py
```

検証器はVidarの一致／不一致を各1件、AMOSの一致／不一致を各1件、FormBookのno-sendを1件含む36件を、numeric localhostだけで実行します。
