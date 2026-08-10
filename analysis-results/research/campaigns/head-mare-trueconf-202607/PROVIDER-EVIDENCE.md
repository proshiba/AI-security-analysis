# provider照合結果

## 要約

2026年8月10日に、一次情報の20個のMD5をMalwareBazaarとVirusTotalへ照合しました。MalwareBazaarは20件すべて未収録、VirusTotalは6件を確認しSHA-256へ展開できました。未収録は検体不存在を意味しません。新規submitは行っていません。

VirusTotalと公開Triageで一致したroot installer `e66bbb6c651b5ab839434b8e62f502169f35894e28dbe9f3275911582eccd250`は、その後、認証付き暗号化archiveとして取得しました。メモリ内でexact hashとサイズを再確認し、非実行静的解析を実施しています。provider labelを独立判定へ置き換えたわけではなく、rootの自動family判定は`unknown`／lowのままです。構造結果は[静的解析](STATIC-ANALYSIS.md)へ分離しました。

| MD5 | 一次情報上の役割 | MalwareBazaar | VirusTotal | 復元SHA-256 |
|---|---|---|---|---|
| `4d27b4eb1c5dbb3d8160f29b8119523e` | `locale.php` WebShell | 未収録 | 確認 | `0ed9306deabddaa587ad75d0775f7e63b27857a13adcc870dc9f8c92a9ddc6da` |
| `748c9f8cb1065000616204935f96207f` | 改ざんTrueConf installer／PhantomCore | 未収録 | 確認 | `e66bbb6c651b5ab839434b8e62f502169f35894e28dbe9f3275911582eccd250` |
| `c5a460e4e68a088f6e51b2c6474642ec` | PhantomCore DLL | 未収録 | 確認 | `b9e4052b310f9451eca9784a4a33bf5282d1bd07e3359eba9648be625e2e40dd` |
| `129462164a7d52e9ea8560b60f0412c5` | PhantomCore DLL／`doc.txt` | 未収録 | 未収録 | — |
| `ec0bf4a2186a88874e9f26f07cfeb532` | PhantomCore DLL／`usocacheddata.txt` | 未収録 | 未収録 | — |
| `b348642146ea34771e5785c5857950f5` | PhantomCore DLL | 未収録 | 未収録 | — |
| `c915cb6c2aeb863ee8479238e1644217` | PhantomCore DLL／`doc.txt` | 未収録 | 未収録 | — |
| `0e79996d9483d1e44fea32b0a48c2c19` | PhantomCore DLL／`doc.txt` | 未収録 | 未収録 | — |
| `2bb75c20e778eb5c416965bd4d4259b1` | 署名なしTrueConf Client EXE | 未収録 | 未収録 | — |
| `b3a6fee3307f1c26841fd5c603e2b013` | PhantomCore DLL／`usocacheddata.txt` | 未収録 | 確認 | `72029a4d4790784dd3029d13e73f57494dcb8f8187ca234b131e2b825bd84336` |
| `8fcc3e4ccbf1725d9989fb464abf3561` | PhantomCore DLL／`usocacheddata.txt` | 未収録 | 確認 | `ceea2f175eaa02919e8b5161c2ecf585de3e8b6d586bca8046eee2e3f4efa386` |
| `489f43be558b2679284ceabed7adc4f3` | PhantomGraph `SysExcSvc.dll` | 未収録 | 未収録 | — |
| `dd1fd2b459b97b7d59375cb8383cd19a` | PhantomGraph `SysReadSvc.dll` | 未収録 | 未収録 | — |
| `0e4541c3153ec5ed01497f19cf4f63d0` | PhantomGraph `SysExcSvc.dll` | 未収録 | 未収録 | — |
| `12d4e8f5295f2ef7e0f9bfc0f4830939` | PhantomGraph `SysExcSvc.dll` | 未収録 | 未収録 | — |
| `7f267006cac10f341c356b62fe493527` | PhantomGraph `SysExcSvc.dll` | 未収録 | 確認 | `0fce4b732ce10c72093587e82ca9747a885430e366934ddc27e437443ff0cc0e` |
| `ee2861d5965e8730708cd1da8a93fa4c` | PhantomGraph `SysExcSvc.dll` | 未収録 | 未収録 | — |
| `c3a2abe8756910f42582b04a44ea3514` | ELF backdoor | 未収録 | 未収録 | — |
| `43f435c3c437bc879a2d7d4634f43494` | ELF backdoor | 未収録 | 未収録 | — |
| `aee9642b45b099cb7f3053b9b680b425` | rootkit | 未収録 | 未収録 | — |

## 6件の既存metadata

| SHA-256 | 種別 | size | provider表示名・label | 解釈 |
|---|---|---:|---|---|
| `0ed9306deabddaa587ad75d0775f7e63b27857a13adcc870dc9f8c92a9ddc6da` | PHP | 34,295 | `locale.php`／`trojan.webshell` | 一次情報のWebShell hashと一致 |
| `e66bbb6c651b5ab839434b8e62f502169f35894e28dbe9f3275911582eccd250` | Win32 EXE | 193,317,970 | TrueConf installer／PhantomCore label | Triage exact hash一致も存在 |
| `b9e4052b310f9451eca9784a4a33bf5282d1bd07e3359eba9648be625e2e40dd` | Win32 DLL | 6,411,264 | PhantomCore label | 一次情報のPhantomCore MD5と一致 |
| `72029a4d4790784dd3029d13e73f57494dcb8f8187ca234b131e2b825bd84336` | Win32 DLL | 6,408,192 | `sbadur/agentagen`系label | 一次情報の役割を優先し、provider label単独で別familyへ再帰属しない |
| `ceea2f175eaa02919e8b5161c2ecf585de3e8b6d586bca8046eee2e3f4efa386` | Win32 DLL | 6,408,192 | `usocacheddata.txt`／`agentagen`系label | 同上 |
| `0fce4b732ce10c72093587e82ca9747a885430e366934ddc27e437443ff0cc0e` | Win32 DLL | 6,411,776 | generic trojan label | 一次情報で`SysExcSvc.dll`とされる。labelだけでPhantomGraph確定とはしない |

VirusTotalのpopular threat nameは検知engineの集約表示であり、独自の設定復元やコード照合ではありません。構造化結果は[provider-evidence.json](provider-evidence.json)へ保存しています。
