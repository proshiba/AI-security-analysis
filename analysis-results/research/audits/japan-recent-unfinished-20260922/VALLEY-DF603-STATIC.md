# ValleyRAT／Gh0stRAT報告検体 `df603ed5…` のInno内層追補

## 対象と結論

既存の[ケース](../../../malware/valleyrat/versions/unknown/cases/df603ed55cbf6f9d74068b956ab966a7b785eb102e1045f343d96255eb2cdc24/README.md)は、MalwareBazaarの`Gh0stRAT` signatureと`ValleyRAT`／`SilverFox` tagが食い違う、終端未取得のInno Setup検体である。今回、ローカルに残る元EXEのSHA-256 `df603ed55cbf6f9d74068b956ab966a7b785eb102e1045f343d96255eb2cdc24` とサイズ5,487,909バイトを照合し、Inno内の4ファイルを実行せずメモリ内で復号した。**ローダー構成と予定起動順序は確認できたが、終端ファミリー、設定、C2は未確定**である。日本国内の感染事例とこのハッシュをつなぐ根拠もない。

元EXEはx86 Inno Setup 6.2.1で、4,559,653バイトのoverlayのSHA-256は`49a65fec8729f35c0df1a50f064a007a33ca22bcc409bea216d2fe5e0311dee7`。通常の展開器では一覧取得に失敗したが、Inno metadataとPascalScriptを静的に解釈し、スクリプト内の**16文字の文字列1件**をXChaCha20保護ファイルの復号入力として照合した。PascalScriptの実行やemulatorは使用していない。今回、子byteを再取得し、リポジトリ外の隔離領域へ保存した。公開成果物には含めない。

## 予定されるファイル配置とプロセス

Inno metadataのAppNameは`App Power Jet`、管理者権限要求、`Uninstallable=no`である。これは設定上の要求であり、実際の昇格・インストール成功を観測したものではない。内部ファイルは次の4件。

| Inno内パス | 復号後の形式・サイズ | SHA-256 | 静的意味 |
|---|---|---|---|
| `{tmp}/../hftptt.exe` | x64 PE、3,330,904バイト | `cd7109c269ecf695f4a7c5a2dc202235f0151d3212d085d02d36abd23c1a7998` | 版情報は`Quark Installer v4.0.0.4`。証明書tableあり、署名妥当性は未検証。 |
| `C:\Users\{user}\AppData\Roaming\hrnnj\hrnnj.exe` | x86 PE、266,704バイト | `c027cf868757babab33686bf4c41192339e04fa89ad868409a5cd4ed90a1f71e` | 版情報は`startbc.exe`／網維大師 APlus Module。`log.dll!GenericLogImpl`をimportする。証明書tableにはHangzhou Shunwang名義証明書があるが、署名妥当性は未検証。 |
| `C:\Users\{user}\AppData\Roaming\hrnnj\log.dll` | x86 PE DLL、80,896バイト | `77ccef7d70e6f1d9dbf54ec9032c6d6eb8d2aa216a3e1d3f898ebd56722f43a3` | `.text`のraw長は0、entry RVA `0x1391f3`は大容量の独自`.OEQa`節内。packer／仮想化されたローダーの疑い。 |
| `C:\Users\{user}\AppData\Roaming\hrnnj\Update.xml` | XMLではないbinary、1,063,858バイト | `e3e24193a585bbdb0825a0e1a6436df082b74769cefcd892aa5fe44d77ed0de7` | entropyは約8.0。内容・復号後の用途は未解決。 |

RunEntriesは、まず`hrnnj.exe 64E0938ABD16B4F698CCB0CC011AFB4F`を`NoWait`で、続いて`{tmp}\..\hftptt.exe`を`ShellExec`／`NoWait`で起動する予定を記す。正確な絶対パスは実行時のユーザー名・一時ディレクトリで変わる。`hrnnj.exe`が`GenericLogImpl`をimportし、`log.dll`が同じ配置先にあるため、DLLサイドロード経路が静的に成立する。ただし、これらはインストーラーの設定とPE importからの**予測**であり、プロセス作成を観測した記録ではない。

PascalScriptの`TAC(langid)`には言語ID `1028`、`2052`、`3076`、`4100`、`1049`に応じた復号入力を返し、それ以外で状態値を設定する条件分岐がある。`InitializeSetup`はその状態値を参照するが、`TAC`の実際の呼出点を確認できていない。したがって「中国語・ロシア語以外では必ず終了する」とは断定しない。

## ファミリーと通信の証拠境界

子4件を対象とした限定的なASCII／UTF-16走査では、旧[ケース記録](../../../malware/valleyrat/versions/unknown/cases/df603ed55cbf6f9d74068b956ab966a7b785eb102e1045f343d96255eb2cdc24/README.md)の`oidng2.duoshit.com`と`51.79.18.52`に一致しなかった。これらは外部相関に基づく推定値のままであり、この検体の設定から確認したC2として扱わない。選択した既存のValleyRAT／Gh0stRAT YARA 3ルールにも子byteの一致はなかったが、これはいずれのファミリーも否定しない。

`log.dll`の高entropyな独自節と`Update.xml`のbinary内容は次の静的復元対象である。終端payloadの形式・コード特性、通信処理、configの値を回収して初めて、提供元ラベルの矛盾を評価できる。今回の結果からValleyRATまたはGh0stRATを確定しない。

## 独自節・設定候補の追加静的追跡

自動復元器の`read_file_and_check`で子4件のInno checksumを検証し、上表のサイズ・SHA-256が再現することを確認した。復元器は埋め込みPascalScriptの逆アセンブル本文から文字列定数だけを抽出し、候補を有界数に限定して検証する。`guess_password`やスクリプトemulatorは呼び出さない。`protected_installer_bundle`の既存handlerに統合し、この元SHA-256を**終端ファミリー未確認のcomponent route**として登録した。通常の検出器でも同handlerが選ばれ、`supports_family_attribution=false`を保持することを実検体で確認した。同構造の検体では内層のファイル名・サイズ・SHA-256を自動出力できる。ただし、これは**Innoの内層復元**であって終端payload復元ではない。

Ghidra MCPでは`/manual/df603/77ccef7d70e6f1d9dbf54ec9032c6d6eb8d2aa216a3e1d3f898ebd56722f43a3.quarantine.bin`を明示selectorとして`log.dll`を解析した。通常の`.text`、`.data`、`.rdata`はraw長0で、実byteの大部分は`.OEQa`節（raw 78,848バイト、entropy 7.63）に集中する。`GenericLogImpl`のexport RVA `0x264f`もraw長0の`.text`内を指し、その表層byteから本来の関数本文を読めない。entry `0x666b91f3`は同節の`0x666c5277`へ相対jumpする。後続には短いjump群、通常のstackフレームから外れた命令列、Ghidra逆コンパイラのbad instruction／stack追跡警告があり、見えている関数を終端RAT本体とみなせない。Detect It Easy 3.21の`VMProtect 2.0.3–2.13`は**heuristic suspicion only**であり、protectorの確定判定ではない。多数のexport名も、本体機能の証拠ではなく、サイドロード成立を補助する表層所見に限る。

`Update.xml`はXMLではなく、全体entropy 7.9998、`PE\x00\x00` headerなし、読める長い平文文字列はほぼない。長さ1,063,858バイトが16で割って余り2となるが、これだけでAESなどの暗号方式を同定しない。`log.dll`の表層には`CreateFileA`、`ReadFile`、`VirtualProtect`、`LoadLibraryA`などのimportがあるが、Ghidraで対応IAT slotへの静的xrefは0件で、`Update.xml`の参照先、復号関数、鍵、展開後のentryは保護コード内で未追跡である。FLOSSの静的文字列には`Update.xml`や旧推定C2は見えなかった。完全FLOSSのstack-string解析は保護コードに対して極端に低速だったため有界時間で中止し、陰性証拠には使っていない。

以上から、子のハッシュと配置、DLLサイドロード、保護コードの存在までは確認済みである一方、**終端コード・家族名・設定・C2・通信protocolは未解決**のままである。外部情報のNoodleRAT等の雑多なハッシュ列挙も、内層コード一致の独立根拠がないため本ケースの帰属には採用しない。次の安全な手順は、`.OEQa`の制御フローと`Update.xml`読込・復号の静的データフローをさらに追跡し、復元後コードのハッシュ・関数・設定構造を独立照合することである。

本検体とは別の、従来の`protected_installer_bundle`登録4件のうち、2件はSetup Factory構造で、このInno専用復元器の対象外である。残る2件は「改変Inno」候補だが、今回のローカル原検体名走査では当該2件のrawを確認できなかったため、**適用可能とも復元成功とも数えない**。本検体`df603…`だけが元byteを照合し、4件復元を実測した対象である。新handlerは未知のInnoでも構造とchecksumが通った場合だけ成功を返し、ファミリー判定へ流用しない。

検体、子PE、DLL、binary blobを実行せず、C2への接続も行っていない。復号した生byte、復号入力、元検体の私有パスは公開成果物に含めない。
