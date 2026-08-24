# RedC2 npm package提供集合（2026-08-24）

外装ZIP SHA-256は`0faeb1ff173c015a83331219c10afefd5a20e69252a1969c661dcfd20209b0cc`、size 142,570 bytesです。password付きZIPを上限付きで復号し、5件のnpm tarballをNode.js/npmへ渡さず静的解析しました。

| package | tarball SHA-256 | ELF path | chmod 0755 | 通常起動見込み |
|---|---|---|---|---|
| `kit-map-vim@1.0.0` | `e3876a8a6098c7fdf285e1320872dbf0ee7ddaed466ae938716b52b0c0a2cc00` | `dist/internal/calc-math.dat` | yes | yes |
| `map-streak-kit@1.0.0` | `f2ed178b376b2d0b8084da698b174e8016ed9863717683462a0fdef15c11f1cd` | `dist/internal/calc-math.dat` | yes | yes |
| `streak-cache-map@1.0.0` | `171aae3329880d35b0e459f895987c5db6f2bdd6e35872aa82bedadfa8dac8fc` | `dist/internal/calc-cache.bin` | yes | yes |
| `streak-map-kit@1.0.0` | `b1d038a04272a1f0dbf1ece8f8697cd140dc7d9cc93dba1719cb916105fa3a37` | `dist/internal/calc-mapping.bin` | yes | yes |
| `streak-metrics-math@1.0.0` | `44c4e793056f661a1e80a2586dc755db2c1d32b7ab25f772fcc39d75d7a1d6ce` | `dist/math-calc.bin` | no | no（mode 0644） |

全件が同一ELF SHA-256 `4537b118...`を内包します。検体・tarball・ELFはrepositoryへ保存していません。
