# ValleyRAT case: eab4918ea7581aececacc1ddf3d86812ea1d203dfae8ab635c66136348e3d534

## 判定とチェーン

`single_pe_direct` 系統。Certum署名付き小型x86 PEがlogon taskを作成し、同一processから2ポートへ接続する。ローカル実行はしていない。

| IOC | 値 |
|---|---|
| SHA-256 | `eab4918ea7581aececacc1ddf3d86812ea1d203dfae8ab635c66136348e3d534` |
| imphash | `eda3c04f4ddf95c5e3607d886ff699c3` |
| C2 | `154.81.37.130:4444`, `154.81.37.130:5555` |
| task | `WinUpdateService` |

```text
schtasks /create /tn "WinUpdateService" /tr "%TEMP%\Open the latest report on the computer.exe" /sc onlogon /rl highest /f
```

C2は元PE PID 3908から両portへの反復接続として観測され、高信頼。`WriteProcessMemory`も観測。Triage: https://tria.ge/reports/260712-t4gq1adt6l/ 。

## Sigma/YARA/Shodan材料

- Sigma: task名＋path＋onlogon/highest、同processから両C2 port、署名済みPEによるWriteProcessMemoryを相関。
- YARA: exact hash/imphash、campaign strings、importsを補助条件化。署名subjectだけでは判定しない。
- 誤検知: task＋path＋C2は低、task名のみ中、署名/WriteProcessMemory単独は高。
- Shodan: `ip:154.81.37.130 (port:4444 or port:5555)`。custom TCPでbanner未取得。

## Behavior and C2 assessment

- Observed chain: a signed x86 PE creates the WinUpdateService logon task and exhibits WriteProcessMemory behavior.
- Expected implant behavior: direct ValleyRAT execution with persistence and remote tasking.
- C2 role: 154.81.37.130:4444 and 154.81.37.130:5555 are interactive endpoints, potentially primary and fallback.
- Evidence: process-attributed sandbox communication.
- Confidence: confirmed.
- Detection: correlate signer context, task creation, memory-write activity, and both endpoints. IP-only detection has high false-positive and short-lifetime risk.
- Family model: [BEHAVIOR-C2.md](../../BEHAVIOR-C2.md)