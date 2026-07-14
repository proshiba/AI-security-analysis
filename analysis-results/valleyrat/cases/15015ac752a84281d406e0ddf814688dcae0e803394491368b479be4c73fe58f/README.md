# ValleyRAT case: 15015ac752a84281d406e0ddf814688dcae0e803394491368b479be4c73fe58f

## 判定とチェーン

`dll_sideload_vvas_bundle` 系統。`chgport.exe`、`LoggerCollector.dll`、`vvaS.bin` が共存する。

```text
HUIYIJIYAO.zip -> chgport.exe + LoggerCollector.dll
 -> vvaS.bin XOR decimal 20 (0x14) -> x86 shellcode
 -> 134.122.128.66:6666 or :8888
```

| IOC | 値 |
|---|---|
| submitted ZIP | `15015ac752a84281d406e0ddf814688dcae0e803394491368b479be4c73fe58f` |
| vvaS.bin | `3b5d6976a3901d21c12ca596651d8c4b0b900dee6db23509d8cf660678bb96ef` |
| decrypted shellcode | `c1adf2fe58ff47af8adbd3e6e6310fa33ca00926f28c33c30d249f4a70846c4c` |
| C2 | `134.122.128.66:6666`, `134.122.128.66:8888` |
| marker | `odaktomk` at `0x474` |
| config dwords | `15, 6666, 1, 15, 8888, 1` |
| distribution | `http://134.122.128.135/HUIYIJIYAO.zip` |

復号configにIPが2回格納され、port構造も確認したため高信頼。配布IPとC2は分離する。Triage: https://tria.ge/reports/260712-ntm75sg15n/ 。sandboxはpayload C2へ到達していない。

## Sigma/YARA/Shodan材料

- YARA: 3ファイル同居、`LoggerCollector-xor20.dll`、復号後のmarker/IP/port構造。
- Sigma: hostによるLoggerCollector load、後続process、C2接続を相関。
- 誤検知: 3ファイル同居＋load edgeは低、hash/IPのみ中、`rundll32.exe`単独は高。
- Shodan: `ip:134.122.128.66 port:6666` / `port:8888`。banner未取得。TCP-openだけではC2稼働を確定しない。

注意: XORキーは16進`0x20`ではなく10進20 (`0x14`)。ローカル実行・ライブ接続はしていない。

## Behavior and C2 assessment

- Observed chain: chgport.exe, LoggerCollector.dll, and vvaS.bin form a DLL side-load bundle; decimal 20 or XOR 0x14 decoding recovers configuration.
- Expected implant behavior: ValleyRAT staged execution and remote tasking.
- C2 role: 134.122.128.66:6666 and 134.122.128.66:8888 are recovered configuration endpoints.
- Evidence: statically decoded configuration; no current protocol validation.
- Confidence: confirmed_config.
- Detection: correlate bundle co-location, DLL load relationship, vvaS marker and XOR routine, and endpoint pair. IP-only matching has high false-positive risk.
- Family model: [BEHAVIOR-C2.md](../../BEHAVIOR-C2.md)