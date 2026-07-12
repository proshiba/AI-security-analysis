# ValleyRAT case: 5bdcf2d4fd8a65c17237d4808e2b613deb0f54de1b90839f1f8e450d8b2acc19

## 判定とチェーン

`installer_overlay_dropper` / SysCEO偽装系。x64 installerがwinget風cacheへside-load bundleを配置する。

```text
Drv_ceo_12.8.1.exe -> C:\winget\...\cache_2C67\dwmhost.exe
 + AliyunWrap.dll / edgestore.dll -> qt64.dat
 -> ValleyRAT S2 v1.0 -> 27.124.18.166:63016 / :63026
```

| Role | SHA-256 / endpoint |
|---|---|
| sample | `5bdcf2d4fd8a65c17237d4808e2b613deb0f54de1b90839f1f8e450d8b2acc19` |
| dwmhost | `c2972fba53e166eb94af5d086b6643fa60632f12bf976fcb25304ce0803d9231` |
| AliyunWrap.dll | `d188594764cfa56c7a1382211f31a982dbda1b1e51792901a29af11f7f93a56e` |
| edgestore.dll | `830bc700ab043b4801bae79e7c4b076ea7ae9c0c6298d63f9ad06b3bd6007c75` |
| stage URL | `https://alidata-1327210346.cos.ap-hongkong.myqcloud.com/qt64.dat` |
| config C2 | `27.124.18.166:63016`, `27.124.18.166:63026` |
| related traffic | `27.124.18.142:443` from child svchost |

Triage configとPID 5136 `dwmhost.exe`の63016反復接続により2つの630xx C2は高信頼。`27.124.18.142:443`は中信頼。Triage: https://tria.ge/reports/260711-23a6tsa16l/ 。

## Sigma/YARA/Shodan材料

- Sigma: System32外のwinget配下dwmhost、同階層DLL load、qt64.dat取得、630xx接続を相関。
- YARA: hashes、DLL名同居、stage URL、S2 config。Tencent COS単独は誤検知が高い。
- 誤検知: path＋hash/C2は低、dwmhost名のみ中～高、COS通信のみ高。
- Shodan: `ip:27.124.18.166 (port:63016 or port:63026)`。関連候補は `ip:27.124.18.142 port:443`。
