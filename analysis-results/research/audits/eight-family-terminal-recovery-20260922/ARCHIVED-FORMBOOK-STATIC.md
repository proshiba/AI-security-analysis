# 保管済みFormbook報告2件の元検体照合と静的再解析

## 対象と元byteの認証

Formbook整理先の`03f46cf9a2de612f87385012e18af57a87e1d227f1fe2b0e8f6f335073104964`と`17b4070f7739accf08ec200d8fe71a65f407afbca9f3f576f42397519f694d2d`について、対象別の暗号化保管物を再取得した。両保管物ともS3のsize／SSE-S3／対象識別子／SHA-256メタデータ、取得ZIPのSHA-256、復号したmanifestのSHA-256、全23 memberのsizeとSHA-256を照合した。各ZIPにroot SHA-256と完全一致するPEが1件あり、sizeは順に1,159,680 byteと1,251,328 byteである。私有保管先や元byteは公開成果物へ含めない。

## 自動静的解析の結果

認証済みroot PEを非実行の`analyze_sample.py`へ入力した。最初の長い私有出力先では、7-Zip追加probeの有無にかかわらず`root_static_analysis_failed (FileNotFoundError)`で停止した。生成済みファイルから、Windowsの長い成果物パスが原因と切り分けた。短い私有出力先では両件とも入力・静的層処理を完走し、解析エラーは0件になった。現在のCLIは既知の最長生成パスを解析開始前に検査し、長すぎる場合は短い`--output`を案内してfail-closedにする。

| root SHA-256 | 静的層数 | 選択されたfamily | route config候補 | case状態 |
|---|---:|---|---:|---|
| `03f46cf9a2de612f87385012e18af57a87e1d227f1fe2b0e8f6f335073104964` | 1（rootのみ） | なし | 0 | `partial` |
| `17b4070f7739accf08ec200d8fe71a65f407afbca9f3f576f42397519f694d2d` | 1（rootのみ） | なし | 0 | `partial` |

PE全体のentropyは順に7.7852、7.6738で、両件とも`.text`が大部分を占め高entropyだった。これは後段復元の優先箇所を示す構造所見であり、保護方式やFormbook帰属を単独で確定しない。自動解析は両件とも子層、終端family、設定、C2を復元しておらず、代表関数解析も未完了である。提供元ラベルを終端familyの証明と扱わず、完了へ昇格しない。

次はrootのentrypointと`.text`の復号・展開ルーチンを静的に調べ、再現可能な変換が得られた場合に上限付きunpackerと回帰試験へ反映する。必要な復号済みbyteが元PE内に見つからない場合は、完全SHA-256一致の公開sandbox後段成果物の有無を別に確認する。検体の実行、CPU／CLRエミュレーション、ライブC2接続は行っていない。
