# 改ざんTrueConf Clientインストーラの静的解析

## 対象と安全境界

| 項目 | 値 |
|---|---|
| ファイル名 | `trueconf_windows_client_x64.exe` |
| SHA-256 | `e66bbb6c651b5ab839434b8e62f502169f35894e28dbe9f3275911582eccd250` |
| サイズ | 193,317,970 bytes |
| 解析方法 | 認証付き暗号化archiveからメモリ内で復号し、非実行の静的解析だけを実施 |
| 実行・外部通信 | なし |
| 公開範囲 | 検体、復号済みpayload、保管先、資格情報をGitへ保存しない |

公開Triageと一次情報の改ざんインストーラにexact hashで一致するroot検体を取得し、SHA-256とサイズを独立確認しました。検体はrepository外で暗号化保管し、保管先側の整合性検証を完了しています。

## 独立確認した構造

| 観測項目 | 結果 | 解釈 |
|---|---|---|
| PE | 32-bit x86 native PE、entry point RVA `0xb0028`、entry section `.itext` | .NET／GoではないInno Setup系native stub |
| section | 11 section、import 149件／5 DLL | process、file、registry、memory、UIを扱う一般的なinstaller能力を持つ |
| Inno識別子 | `JR.Inno.Setup`、`SetupLdrAndSetup`、`Inno Setup Setup Data (6.5.2)` | Inno Setup 6.5.2で構築されたことを強く支持 |
| overlay | offset `0x11ba00`、192,156,242 bytes、全体の99.3991% | 実payloadの大半がstub外のopaque overlayに格納されている |
| 資源 | 51 resourceを全件走査。PNG 3件を確認 | PNG内に別形式を隠した証拠は得られなかった |
| 埋め込みPE走査 | `MZ`候補2,925件を全域で検証し、妥当なPEは0件 | 高entropy data中の偶然一致をPEとして誤復元しない |
| container probe | 7-Zipではarchive memberを列挙できず、exit code 2 | 通常の7-Zip containerとしては展開できない |
| family判定 | `unknown`／low、該当handlerなし | exact hashのOSINT帰属と、独立静的family判定を混同しない |

PE sectionを含むstub領域は1,161,728 bytesで、残り約192 MBがoverlayです。`Inno Setup Setup Data (6.5.2)`はoverlay内のoffset `0xb72cee4`でも確認できました。一方、legacy Inno data markerとして使われることがある`rDlPtS02`は見つかりませんでした。version差、保護、独自変更のどれかは、この観測だけでは確定できません。

entropyは計算範囲により値が異なります。全体byte列の計算は7.9998、上限付きsample計算は7.769で、いずれも巨大overlayが圧縮または暗号化されたdataである可能性を支持します。ただし、高entropyだけで暗号方式や悪性payloadを確定しません。

## rootロジックと未復元区間

```mermaid
flowchart LR
    A["認証付き暗号化archive"] --> B["exact-hash root PE"]
    B --> C["Inno Setup 6.5.2 x86 stub"]
    C --> D["99.3991% opaque overlay"]
    D -. "静的抽出未完了" .-> E["子file／PhantomCore候補"]
    E -. "公開sandboxで観測" .-> F["TrueConf.exe＋悪性DLL"]
    F -. "公開sandboxで観測" .-> G["固定CLSID InprocServer32"]
```

stubのimportと文字列から、`CreateProcessW`、file／directory操作、registry操作、権限token参照、`VirtualAlloc`／`VirtualProtect`、thread制御などを確認しました。これらはInno Setup installer自身にも必要な機能であり、importだけをPhantomCoreの実行証拠として扱いません。

文字列には`AppMutex`、`NumRegistryEntries`、`/PASSWORD=`、`sccPasswordTest`などInno Setup共通ロジックが含まれます。`/PASSWORD=`の存在はstubの共通機能を示すだけで、この検体のpayloadがpassword保護されている証拠ではありません。

## payload、設定、C2の結果

- root検体から子fileを復元できず、PhantomCore DLLのhashを独立抽出できませんでした。
- providerで確認済みのPhantomCore候補`b9e4052b310f9451eca9784a4a33bf5282d1bd07e3359eba9648be625e2e40dd`はcampaign関連artifactですが、この静的処理でrootから得たhashではありません。
- root文字列からcampaign固有のC2 endpoint、設定blob、check-in fieldは復元できませんでした。
- `jrsoftware.org`とMicrosoft schema URLはinstaller／manifest文脈の正規参照であり、IOCまたはC2へ昇格しません。
- 一次情報のPhantomGraph／OneDrive経路はServer側の別分岐です。root Client installerから一般的なMicrosoft endpointを抽出してC2とみなしません。

## 解析がpartialとなった理由

1. 実payload領域が、通常のPE sectionではなく巨大なInno Setup overlayに収容されています。
2. 全域走査で得た`MZ`候補はすべてPE header検証に失敗し、carvingによる安全な復元ができませんでした。
3. 7-ZipはInno Setup 6.5.2 dataをmemberとして列挙できず、この環境に対応する専用Inno extractorはありませんでした。
4. 文字列走査は100,000件で上限に達しました。高entropy data由来のnoiseが多く、endpoint候補を信頼できる設定として昇格できませんでした。
5. 子DLLを復元できていないため、Ghidraで優先すべきPhantomCore関数、設定復号関数、C2関数の入口が存在しません。installer stubだけの逆コンパイルは、payloadのprotocol解明には直結しません。

## 次の静的解析手順

1. Inno Setup 6.5.2 data headerとchunk tableに対応する非実行extractorを追加し、offset `0xb72cee4`周辺からfile tableを復元する。
2. 復元物のSHA-256、PE妥当性、署名、配置先を記録し、既知PhantomCore artifactとはexact hashまたはコード類似性で比較する。
3. 子DLLが得られた時点でGhidraへimportし、entry point、設定復号、COM registration、network処理の代表関数を逆コンパイルする。
4. 静的復元が失敗する場合に限り、公開sandboxのmemory dumpまたはdropped artifactを取得し、その構造からextractorの不足処理を逆算する。

現時点の独立結論は「exact-hashのrootはInno Setup 6.5.2系installerで、99.4%を占めるopaque overlayを持つ」までです。PhantomCore帰属とCOM hijackは一次情報／公開sandboxで強く補強されますが、rootからの子payload復元、C2設定復元、protocol確認は未完了です。
