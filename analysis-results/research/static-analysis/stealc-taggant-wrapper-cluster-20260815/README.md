# StealC保護外層clusterの追加静的解析

## 結論

取得・SHA-256照合できた11件を、検体を実行せずに比較した。全件でx86の7 section構成、`kernel32.dll`だけの1 import、ランダム化された2つの実行section、`.taggant` entrypoint、4 basic block・3 edge・1 call・`INT3`終端が一致した。

この一致は同じ保護外層lineageを高い確度で示す。一方、外層だけではThemida／WinLicenseの正確な版、内側のStealC payload、検体固有の設定・C2を確定しない。従って終端復元blockerは維持する。

## 入口stubの追加相関

11件の入口CFGを追加比較した結果、命令数は16～36で変動したが、全件でbranchは3本の無条件分岐だけだった。条件分岐と間接分岐は0、循環的複雑度は1、direct callは1、終端は`INT3`で一致した。

全件共通mnemonicは`call`、`int3`、`jmp`、`mov`、`push`、`sub`であり、変動mnemonicは`add`、`and`、`dec`、`inc`、`not`、`pop`、`shl`、`shr`、`xchg`、`xor`だった。この差は入口stubの整数演算やjunk変異と整合するが、正確なprotector版の根拠には使わない。

## 固定fingerprint

- cluster ID：`stealc-taggant-wrapper-466909e3ef5d175a`
- 構造fingerprint SHA-256：`466909e3ef5d175acc1f3923245a3f8069248bfe78def549965adbee1522e331`
- 対象件数：11件
- 検体実行：なし
- CPU emulation：なし
- マルウェア／C2への接続：なし
- provider archive取得：別工程のexact-hash downloadのみ

## case別観測

| SHA-256 | size | entropy | ランダムsection | resource | entrypoint命令数 |
|---|---:|---:|---|---:|---:|
| [`09034743ead73365c3077a85036d69c4ef0b0c19bba669db7cd53814b9308889`](../../../malware/stealc/versions/unknown/cases/09034743ead73365c3077a85036d69c4ef0b0c19bba669db7cd53814b9308889/README.md) | 1,837,056 | 7.9460 | `lculjkhe` / `ezzbfwjh` | 0 | 16 |
| [`125382411e94398dd47ef364807868a3d2a6a4d4821d1513897278e77ef005b1`](../../../malware/stealc/versions/unknown/cases/125382411e94398dd47ef364807868a3d2a6a4d4821d1513897278e77ef005b1/README.md) | 1,783,808 | 7.9444 | `oggjeoxe` / `bpbnhoje` | 0 | 21 |
| [`299c378868c76048c26d0e279655c08305f0ce42e5582fe5005aae776d525a1b`](../../../malware/stealc/versions/unknown/cases/299c378868c76048c26d0e279655c08305f0ce42e5582fe5005aae776d525a1b/README.md) | 1,798,144 | 7.9436 | `ibsbbfsz` / `xnkbybmp` | 0 | 31 |
| [`99e3eaac03d77c6b24ebd5a17326ba051788d58f1f1d4aa6871310419a85d8af`](../../../malware/stealc/versions/unknown/cases/99e3eaac03d77c6b24ebd5a17326ba051788d58f1f1d4aa6871310419a85d8af/README.md) | 1,745,408 | 7.9442 | `nsriuoot` / `fcgomrub` | 0 | 17 |
| [`9b8e5b5f2e62640327fdd1616c62a29ec27eaddad731d66ed331b3a1135fd6cb`](../../../malware/stealc/versions/unknown/cases/9b8e5b5f2e62640327fdd1616c62a29ec27eaddad731d66ed331b3a1135fd6cb/README.md) | 1,764,864 | 7.9458 | `nvgmvkfs` / `mvlvetrb` | 0 | 27 |
| [`ab5f78eaccc4a0f86106c547f828c2da8bd554a855deda50074c8a3cd003513a`](../../../malware/stealc/versions/unknown/cases/ab5f78eaccc4a0f86106c547f828c2da8bd554a855deda50074c8a3cd003513a/README.md) | 1,756,672 | 7.9436 | `dnbdzjvd` / `hwzrywcd` | 0 | 36 |
| [`b42f055a7a568843360e4b8b46d514de26931303b039b700d15a336b5c53dc0b`](../../../malware/stealc/versions/unknown/cases/b42f055a7a568843360e4b8b46d514de26931303b039b700d15a336b5c53dc0b/README.md) | 1,811,968 | 7.9430 | `cpbdjvhh` / `btxydvwq` | 0 | 26 |
| [`e08a69c8611950c16a0d273800acc6083cce9078358a8ff41b4639e02a7b18b0`](../../../malware/stealc/versions/unknown/cases/e08a69c8611950c16a0d273800acc6083cce9078358a8ff41b4639e02a7b18b0/README.md) | 1,795,584 | 7.9451 | `cgmytlif` / `rvymqypd` | 0 | 21 |
| [`e1bdbadb3c03238af26c510775bb0aa63f7221dd43eb6f02a16332e091718779`](../../../malware/stealc/versions/unknown/cases/e1bdbadb3c03238af26c510775bb0aa63f7221dd43eb6f02a16332e091718779/README.md) | 1,822,720 | 7.9458 | `slkfwdkq` / `tyqcqcio` | 1 | 26 |
| [`eb433e78acbf8dc7dfd0817a7699ebef2b44c5de873aa3cb9e950d7df895d49a`](../../../malware/stealc/versions/unknown/cases/eb433e78acbf8dc7dfd0817a7699ebef2b44c5de873aa3cb9e950d7df895d49a/README.md) | 1,814,528 | 7.9423 | `esdzurwm` / `gpsgltzd` | 1 | 25 |
| [`f0947eaff9837140af164952d5ff422e3f9e35cea5c85a67709fb97638d03f12`](../../../malware/stealc/versions/unknown/cases/f0947eaff9837140af164952d5ff422e3f9e35cea5c85a67709fb97638d03f12/README.md) | 1,792,000 | 7.9441 | `lxojhmjk` / `mdoopayt` | 0 | 24 |

## 自動handlerへの接続

review済み11件を共通one-shot経路で再解析し、全件でexact SHA-256とbyte-levelの7 section構造を同時照合した。StealC handlerは全件でtier 2（`structural_corroboration`）を返し、従来の`no_evidence`を解消した。

この自動化は保護外層の構造証拠だけを扱う。Themida／WinLicenseの解除、終端payload、設定、C2は未復元のままであり、IOC候補は生成しない。

- handler ID：`stealc:extractors.stealc.extractor.py:extract`
- handler source SHA-256：`82aef189fcdb6c22f2ba0fba4b4754f20090c4cdf774199b940b766eeb48d48d`
- 検体実行：なし
- 外部通信：なし

## 残る制約

- `.taggant`とsection topologyはprotector lineageの証拠であり、StealC終端payloadの独立確認ではない。
- 入口stubの命令数差はjunk命令の変異と整合するが、正確なprotector版の根拠には使わない。
- 設定・C2は平文終端payloadが静的に復元されるまで未回収のままとする。
