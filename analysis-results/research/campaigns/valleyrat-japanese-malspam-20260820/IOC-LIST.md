# IOC一覧

## 悪性・防御利用向け

| 種別 | 値 | 役割 | 確度 |
|---|---|---|---|
| URL | `hxxps://dnbwr-rtw4u.pages[.]dev` | 1件目の配布page | 高（公開観測） |
| Domain | `fshsjlk[.]cc` | 1件目C2名 | 高（公開観測） |
| IP:Port | `121.127.253[.]206:8856` | 1件目stage channel | 高（PCAP） |
| IP:Port | `121.127.253[.]206:8868` | 1件目control channel | 高（PCAP） |
| IP:Port | `170.62.130[.]47:449` | 2件目stage／control | 高（PCAP） |
| IP:Port | `170.62.130[.]47:443` | 2件目静的config | 中（未接続） |
| IP:Port | `202.61.140[.]222:448` | 3件目stage／control | 高（静的＋PCAP） |
| SHA-256 | `d01d4a086d19d7be96383aeea7538dfbf364510354d997645e6f8ec11454c50b` | 1件目ZIP | 高 |
| SHA-256 | `05cce219ba84d0e650fb310b42a1734c86fe8a51b0cee199c645fb9e1c59f5d0` | 1件目IMG | 高 |
| SHA-256 | `da33a95b2ed28e2c50da002584eb81e4e94fe4a55e98945146842ed9e23be066` | 悪性`nW_Elf.dLL` | 高 |
| SHA-256 | `4df8bda2718afbd6ee42a96e0097d24592e451a1c6a05d9bffa8921c683733e2` | 1件目PCAP復元x86 stage | 高 |
| SHA-256 | `75a3ae5489d181f3b219c0d1d79ec60046f19a0e5274f30f604020ea4a1fd0a6` | 2件目ZIP | 高 |
| SHA-256 | `07c5ab781ab5989f07676207334fd196b0f1932acdbd00d8346e2d4600e02e57` | 2件目IMG | 高 |
| SHA-256 | `22d1b5576ccb3c425a94e405076a0665efa0dd2d59325bfb561b6b16969e267f` | 悪性`vulkan-1.dll` | 高 |
| SHA-256 | `807361fe1ff663ff3716a7e667e964f9d8fd15a20766bd2796bd46b1f67e168e` | 2件目PCAP復元x64 stage | 高 |
| SHA-256 | `b326409c142eb8cb0793506c2c27187bba5f96e3986cda09b2ef3eb47811d3bf` | 3件目IMG variant 1 | 高 |
| SHA-256 | `8b141a7c5d8af94ed37ea2b5dd676f9cb105ba8a6eedda36349899a2f1d065ff` | 3件目IMG variant 2 | 高 |
| SHA-256 | `810e53107d0c6ced27f5f957d30981f5640c62b930bf4e30c9028b73b06c5cca` | 3件目IMG variant 3 | 高 |
| SHA-256 | `041a0aeb76e63f67abb258036b089e27174074c5367d7c7a2a644e3bf9dd3b51` | 悪性`MSOCF.dll` variant 1 | 高 |
| SHA-256 | `04c9eae9f19a63e4a84da108fe6b768ab6e558c89126dbb6c35a0c383739a81f` | 悪性`MSOCF.dll` variant 2 | 高 |
| SHA-256 | `ad755d2dfeaa23b80d561656848d12d8e66edd99b1169d63a936fe7b01da57ab` | 悪性`MSOCF.dll` variant 3 | 高 |
| Imphash | `fc1d45e2b662c656e1a56e88c9fc63e6` | 3 MSOCF共通 | 高 |
| SHA-256 | `c77c885cae806025691827fa44ad1e40cdb737713473979212e0c986ceafdbf0` | 3 MSOCF共通復号stage | 高 |
| SHA-256 | `ff5dbdcf6d7ae5d97b6f3ef412df0b977ba4a844c45b30ca78c0eeb2653d69a8` | `kvckiller.sys` | 高 |
| SHA-256 | `ce6bb7eddc83762c708d4a41709ae00371dbdc09b2a380f28fa60b1edf917473` | `svchostsr.exe` | 高 |
| Path | `C:\ProgramData\OpenraVPN\vulkan-1.dll` | 2件目悪性DLL配置先 | 高 |
| Path | `C:\ProgramData\OpenraVPN\Loader.exe` | 2件目side-load host配置先 | 高 |
| Path | `C:\Users\Public\svchostsr.exe` | 3件目永続payload | 高 |
| Path | `C:\Windows\System32\drivers\kvckiller.sys` | 3件目driver | 高 |
| Registry | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ServiceController` | 2件目永続化 | 高 |
| Registry | `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Microsoft Office` | 3件目永続化 | 高 |
| Service | `EmbeddedDriverService` | 3件目driver service | 高 |
| Firewall rule | `RemoteController_Inbound_Rule` | 2件目通信許可 | 高（静的） |
| Firewall rule | `RemoteController_Outbound_Rule` | 2件目通信許可 | 高（静的） |

## Context-only／単体block非推奨

次のhashは正規署名hostまたはruntimeです。悪性bundleとの組合せ検知には使えますが、hash単体でblockしません。

| SHA-256 | File | 理由 |
|---|---|---|
| `4bfa832e0b5d59d5498d85071020167e97b06c69aa43cca2cfccd0c91d535c1d` | `CIT-Number.20260824112143.EXE` | 正規署名side-load host |
| `facf78d474b66ed821288db41fa6ad8a7b6f30650eb12127cb3e9a3cc6146116` | `2026081829618475_setup.exe`／`Loader.exe` | 正規Intel署名host |
| `5d8d20ab8008d5e8cd6ff7b44273fc4a13d30e97d1c7b295aa0786da7ac1f9e3` | `20260824.EXE` | 正規Microsoft署名host |
| `d769fafa2b3232de9fa7153212ba287f68e745257f1c00fafb511e7a02de7adf` | `msvcp100.dll` | 正規runtime |
| `60c06e0fa4449314da3a0a87c1a9d9577df99226f943637e06f61188e5862efa` | `msvcr100.dll` | 正規runtime |

`NvDLISR.{GUID}`、SID風directory、`prj????.tmp`、mounted drive letter、CLSIDはrun／variantごとに変化するため、完全一致ではなく周辺挙動と組み合わせます。
