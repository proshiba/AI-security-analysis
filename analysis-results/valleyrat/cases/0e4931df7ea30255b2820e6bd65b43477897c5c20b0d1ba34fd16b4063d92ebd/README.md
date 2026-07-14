# ValleyRAT case: 0e4931df7ea30255b2820e6bd65b43477897c5c20b0d1ba34fd16b4063d92ebd

## 判定とチェーン

`msi_embedded_pe_staged_download` 系統。MSI custom actionから複数stageを取得し、最終hostがcustom TCP C2へ接続する。

```text
app_setup.6653008.msi -> msiexec -> C:\Users\Public\z80Zba\ayGZ6B.exe
 -> OSS stage downloads -> C:\Program Files (x86)\34UXpv\34UXpv.exe
 + XPSPLOG.dll -> tlhcoz.net DNS -> 8.210.15.149:28300
```

| IOC | 値 |
|---|---|
| MSI | `0e4931df7ea30255b2820e6bd65b43477897c5c20b0d1ba34fd16b4063d92ebd` |
| embedded PE | `e87483fa8d7dfff8a2f7f64047cce868ff29486e63b7ba07859b3acdc145b1c7` |
| final host | `6d6ba2bc9ad414837826f7278bc3e0116f1aeda02d0c2284ed65819f5d9180a8` |
| XPSPLOG.dll | `195eb165c298333e3a9616f67d1171a94f4402cbeb2ba1f0e6acf0d471222f9f` |
| stage domains | `710new.oss-cn-beijing.aliyuncs.com`, `26nn.oss-cn-hangzhou.aliyuncs.com` |
| DNS pivot | `tlhcoz.net` |
| final C2 | `8.210.15.149:28300` |

PID 3028 `34UXpv.exe`がdomainを反復照会しendpointへ接続したため高信頼。OSSは配布先でありC2と分離。Triage: https://tria.ge/reports/260711-21dh6sa14k/ 。

防御回避ではSYSTEM/highestの一時task `Task1`をCreate→Run→Deleteし、Defender exclusionへUsers、ProgramData、Program Files等を広範に追加する。

## Sigma/YARA/Shodan材料

- Sigma: task時系列＋Defender除外、34UXpv/XPSPLOG load、domain照会、28300接続を相関。
- YARA: final hashes、filenames、stage names、MSI embedded PE構造。
- 誤検知: 一連のtask＋広範除外は低、OSS domainのみ中～高、msiexec単独は高。
- Shodan: `ip:8.210.15.149 port:28300`。custom TCPでbanner未取得。`hostname:tlhcoz.net`はDNS pivotに限定。

## Behavior and C2 assessment

- Observed chain: MSI custom actions launch multiple stages, retrieve content from object storage, create a SYSTEM or highest-privilege task, weaken Defender, and execute 34UXpv.exe with XPSPLOG.dll.
- Expected implant behavior: persistent staged ValleyRAT execution and remote tasking.
- C2 role: object-storage URLs are distribution only; 8.210.15.149:28300 is the final process-attributed C2. tlhcoz.net is a related DNS pivot.
- Evidence: sandbox process, DNS, and network attribution.
- Confidence: confirmed.
- Detection: correlate MSI actions, distribution-to-final-host transition, task and Defender changes, host/DLL relationship, and final endpoint. Object-storage-only detection is noisy.
- Family model: [BEHAVIOR-C2.md](../../BEHAVIOR-C2.md)