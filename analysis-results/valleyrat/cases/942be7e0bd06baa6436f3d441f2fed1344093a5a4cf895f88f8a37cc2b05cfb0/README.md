# ValleyRAT case: 942be7e0bd06baa6436f3d441f2fed1344093a5a4cf895f88f8a37cc2b05cfb0

## 判定とチェーン

`installer_overlay_dropper` 系統のx86 installer（overlay 25,166,502 bytes）。ローカル実行はしていない。

```text
pfd26312000003381626281setup.exe -> %TEMP%\...tmp
 -> C:\Program Files\ponyl0r6\NASM\setup.exe
 -> %LOCALAPPDATA%\Microsoft\setup.exe -> 150.158.50.175:443
```

| IOC | 値 |
|---|---|
| sample SHA-256 | `942be7e0bd06baa6436f3d441f2fed1344093a5a4cf895f88f8a37cc2b05cfb0` |
| imphash | `88016fcdef7f227c62171d0afad9aae4` |
| dropped setup | `8cf65e0cef5b5de362c8ddcc77e82a6fdbbcad843939fcc11c47f80d3f45834a` |
| temporary setup | `9f8d02cd4740e66df054f0d55ec14299f909f6d6ece5e87ec8f0c148d154cb1e` |
| driver | `2f0b16ed90b8c15bf52a7c32699dbe0dbcd38fc02ed2ddb4e1ba35487177b6c5` |
| C2 | `150.158.50.175:443/TCP` |

C2は配置後の `setup.exe` PID 3680/5656から反復接続として観測され、高信頼。Triage: https://tria.ge/reports/260712-t422yadt7k/ 。

## Sigma/YARA/Shodan材料

- Sigma: 固有親子chain、`ponyl0r6\NASM`からLocalAppDataへの配置、同processからC2への接続を相関。
- YARA: hashes、imphash、巨大overlay、campaign path。overlayまたは`setup.exe`名単独は一般installerで誤検知が高い。
- 誤検知: hash＋C2は低、固有path＋子processは低～中、443またはfilename単独は高。
- Shodan: `ip:150.158.50.175 port:443`。banner、証明書hash、JARMは未取得。IP再割当を考慮する。

## Behavior and C2 assessment

- Observed chain: a large-overlay x86 installer stages setup content under temporary, Program Files, or LocalAppData paths and launches setup.exe.
- Expected implant behavior: a staged host establishes ValleyRAT remote-control communication.
- C2 role: 150.158.50.175:443 is an interactive C2 candidate attributed to the launched process.
- Evidence: sandbox process and network correlation.
- Confidence: confirmed.
- Detection: combine overlay installer traits, staging paths, setup.exe ancestry, and process-attributed network activity. Port 443 alone is not useful.
- Family model: [BEHAVIOR-C2.md](../../BEHAVIOR-C2.md)