# AsyncRAT整理先2件の再静的解析（2026-09-22）

この文書の「AsyncRAT」は既存台帳の整理先であり、終端のファミリー認定ではない。検体、子payload、managed CILを実行せず、外部ホストにも接続していない。子byteと設定は隔離した私有解析領域だけで扱い、以下には再ハッシュ済みの識別子と検証済みの判断を記す。

## `f6f7dbd6561e7ee6ba7e6abffdb1e5de01bf511318aade34825d888e99db645f`

元の暗号化ZIPのmemberを認証してroot SHA-256に完全一致することを確認した。新しい静的復元器では、107,832 byteのPEから逆順チャンク・affine XOR変換で82,271 byteのDonut層 `c718933556c1eba4b8bc1e1e8d91e3579cb27a65e6bf6ab92b65a9061255e825`を得て、そこから64,512 byteの.NET PE `8e07ec3b2017e3be75d8d3d56a847f705ac6389427471ed52481cef870351600`へ到達した。復元層は3、制限超過は0で、別の私有解析が保持していた終端PEともSHA-256が一致した。

終端PEの設定は、sample固有saltを静的initializerから取得し、HMAC-SHA256を検証してからAES-256-CBCで復号できた。設定中の自己表記は`BwRat  1.0.0`、グループは`Default`、構成上のendpointは`112.213.103.17:1217`である。`.NET`のSettings構造、packet field、登録・keepaliveのCIL構造はDCRat互換profileに一致する。ただし、この互換extractorの名前は終端ファミリーがDCRatであるという独立証拠ではない。従来の私有解析ではBwRat／VenomRAT protocol lineageと評価されており、外部提供元のAsyncRATラベルと矛盾する。したがって現在のファミリー認定は保留する。endpointは認証済み静的設定値であり、現在の稼働や実通信先との一致は未確認である。

新しい自動解析の`static-layers.json`は親子関係を再現した。追加した`handler-config-candidates.json`は、認証済み設定を`source_profile=dcrat`、`self_declared_product=bwrat`、`family_attribution_confirmed=false`、`used_for_c2_confirmation=false`として保持する。再実行で`orchestration.family_resolution=unresolved`、`report.classification.automation_family=null`を確認し、互換profileからDCRatへ誤確定する経路を止めた。`route-config-candidates.json`はfamily帰属が未確定のため`assessment_rejected`のまま、function-levelの必須解析も未完了である。復元済み終端byteと設定の存在と、公開caseの完了判定は分けて扱う。

## `3610fcc54a204281b09095004f02b674cd75bdd83996a1428fdef85645eff3e1`

暗号化ZIPのmemberを認証し、root SHA-256の一致を確認した。既定の自動解析ではrootのみだったが、上限付き7-Zip container probeを明示した再解析では、NSIS-Park-1 Unicode内の3 memberを非実行で抽出した。

| member | SHA-256 | byte数 | 観測 |
|---|---|---:|---|
| `11.exe` | `db413d7a7f36a922d30489d4df22d8fecd4da3a6e08f0a227ca770d6afa24bc3` | 206,920 | x64 PE。`dbgeng.dll`の`DebugCreate`、`DebugConnectWide`をimport |
| `dbgeng.dll` | `5c19d5539749b0b0264d5b482731081d411b7168d0010233cf38c6fb24f4d1ac` | 427,520 | x64 PE。上記exportと`png.dat`文字列を確認 |
| `png.dat` | `33ab95f004aec7e6c5024ca79d63e416eff15a2626485a481be265de45eaa0f4` | 113,246 | 先頭`MLEN`、高エントロピーのdata |

さらに`11.exe`のPE resourceから23,648 byteのPE `39a976ac4e1b76c2058815c5017bd3acceb69950286cfdf8c5704b7e31b8cca0`を抽出した。これらは子componentの存在を証明するが、NSIS scriptから起動順序を一意に復元できず、`png.dat`の復号形式や最終payloadは未確認である。DLL sideloadingの疑いはimport/exportと同居ファイル名による静的推論にとどめ、実際のprocess挙動やファミリーを確定しない。`report.json`も`classification.family=unknown`、`case_state.complete=false`のままである。

## 自動化へ戻す条件

`f6f7...`では復元済み子PEの独立した系統判定とfunction-level根拠を加え、設定抽出profile名とファミリー名を混同しない品質ゲートを通す。`3610...`ではNSIS memberの検証済み静的抽出を既定経路へ取り込み、`dbgeng.dll`の`png.dat`読取・復号関数と`11.exe`の実行関係を非実行で解析する。どちらも終端のfamily、設定、親子関係が揃うまで「完了」と表示しない。
