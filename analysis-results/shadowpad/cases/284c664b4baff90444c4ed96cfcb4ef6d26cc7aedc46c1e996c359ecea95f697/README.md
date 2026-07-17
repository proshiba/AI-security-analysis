# ShadowPad case 284c664b4baff90444c4ed96cfcb4ef6d26cc7aedc46c1e996c359ecea95f697

- Source: VX-Underground ShadowPad collection
- Artifact: 131,584-byte x64 native PE
- Pattern: `casper_goods_kankuedu`
- Analysis: static only; no execution and no endpoint contact

## Decryption and configuration

The outer seed is at RVA `0xa260`. The x64 key schedule recovered a proprietary Root module, five embedded modules, and a single-byte-XOR/QuickLZ Config block at decoded offset `0x4bf7`. Module ID 102 contains the x64 string schedule; reversing it enabled complete 0x85c-byte config recovery.

Campaign ID is `3vS89RZxQNWSgQTu1`. Installation masquerades as `Remote RT` / `Remote Registry Tools` at `%SystemRoot%\System32\ras\remote.exe`, with `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and value `Remote Registry`. Three injection-target slots are empty; the fallback is `%windir%\system32\svchost.exe`.

## C2 and IOC evidence

The only server string is `https://goods.kankuedu.org`. It is a confirmed static config URL. No explicit port is encoded, so HTTPS convention implies 443 only as an inference; the IOC record does not add an unobserved port.

## Detection material

High-confidence static detection uses the x64 outer key schedule, Config flags, 0x85c layout, module ID 102, and x64 string-key constants. `remote.exe`, Remote Registry wording, and Run-key activity alone are high-noise administrator/service patterns. Correlate them with the exact path and config URL.

