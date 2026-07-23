# 関数コード類似性索引

各caseの `static-logic.json` にある正規化fingerprintを相関した索引です。
一致はコード共有の手掛かりであり、ファミリー、actor、campaignの確定ではありません。

## 集計

| 項目 | 件数 |
|---|---:|
| static-logic.json | 20 |
| 関数・処理単位 | 35 |
| 完全一致group | 4 |
| 類似候補pair | 44 |

## 類似候補

| 左case／関数 | 右case／関数 | 類似度 | 同一ファミリー |
|---|---|---:|---|
| `1220d2250778:RecoverPumpedPythonRuntime@archive:python37.dll` | `14ac0c55100d:RecoverPumpedPythonRuntime@archive:python37.dll` | 1.0000 | はい |
| `1220d2250778:RecoverPumpedPythonRuntime@archive:python37.dll` | `7c9a76145f39:RecoverPumpedPythonRuntime@archive:python37.dll` | 1.0000 | はい |
| `1220d2250778:RecoverPumpedPythonRuntime@archive:python37.dll` | `c4b117f30786:RecoverPumpedPythonRuntime@archive:python37.dll` | 1.0000 | はい |
| `1220d2250778:PythonRuntimeEntry@101bc689` | `14ac0c55100d:PythonRuntimeEntry@101bc689` | 1.0000 | はい |
| `1220d2250778:PythonRuntimeEntry@101bc689` | `7c9a76145f39:PythonRuntimeEntry@101bc689` | 1.0000 | はい |
| `1220d2250778:PythonRuntimeEntry@101bc689` | `c4b117f30786:PythonRuntimeEntry@101bc689` | 1.0000 | はい |
| `1220d2250778:EnumerateEmbeddedPEResources@pe:.rsrc` | `14ac0c55100d:EnumerateEmbeddedPEResources@pe:.rsrc` | 1.0000 | はい |
| `1220d2250778:EnumerateEmbeddedPEResources@pe:.rsrc` | `7c9a76145f39:EnumerateEmbeddedPEResources@pe:.rsrc` | 1.0000 | はい |
| `1220d2250778:EnumerateEmbeddedPEResources@pe:.rsrc` | `c4b117f30786:EnumerateEmbeddedPEResources@pe:.rsrc` | 1.0000 | はい |
| `14ac0c55100d:RecoverPumpedPythonRuntime@archive:python37.dll` | `7c9a76145f39:RecoverPumpedPythonRuntime@archive:python37.dll` | 1.0000 | はい |
| `14ac0c55100d:RecoverPumpedPythonRuntime@archive:python37.dll` | `c4b117f30786:RecoverPumpedPythonRuntime@archive:python37.dll` | 1.0000 | はい |
| `14ac0c55100d:PythonRuntimeEntry@101bc689` | `7c9a76145f39:PythonRuntimeEntry@101bc689` | 1.0000 | はい |
| `14ac0c55100d:PythonRuntimeEntry@101bc689` | `c4b117f30786:PythonRuntimeEntry@101bc689` | 1.0000 | はい |
| `14ac0c55100d:EnumerateEmbeddedPEResources@pe:.rsrc` | `7c9a76145f39:EnumerateEmbeddedPEResources@pe:.rsrc` | 1.0000 | はい |
| `14ac0c55100d:EnumerateEmbeddedPEResources@pe:.rsrc` | `c4b117f30786:EnumerateEmbeddedPEResources@pe:.rsrc` | 1.0000 | はい |
| `7c9a76145f39:RecoverPumpedPythonRuntime@archive:python37.dll` | `c4b117f30786:RecoverPumpedPythonRuntime@archive:python37.dll` | 1.0000 | はい |
| `7c9a76145f39:PythonRuntimeEntry@101bc689` | `c4b117f30786:PythonRuntimeEntry@101bc689` | 1.0000 | はい |
| `7c9a76145f39:EnumerateEmbeddedPEResources@pe:.rsrc` | `c4b117f30786:EnumerateEmbeddedPEResources@pe:.rsrc` | 1.0000 | はい |
| `12b920865bc8:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `5f8daf53ef21:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.9531 | はい |
| `12b920865bc8:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `8715bb53fad9:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.9062 | はい |
| `12b920865bc8:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `9a9d372cc821:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.9531 | はい |
| `12b920865bc8:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `a0d1e6b47152:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.9375 | はい |
| `12b920865bc8:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `a0eb29beacb4:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.9062 | はい |
| `12b920865bc8:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `edb371be3967:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.9531 | はい |
| `5876be168613:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `8715bb53fad9:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.9219 | はい |
| `5876be168613:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `9a9d372cc821:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.9375 | はい |
| `5876be168613:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `a0d1e6b47152:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.9219 | はい |
| `5876be168613:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `a0eb29beacb4:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.9219 | はい |
| `5876be168613:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `edb371be3967:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.9375 | はい |
| `5f8daf53ef21:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `8715bb53fad9:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.9219 | はい |
| `5f8daf53ef21:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `9a9d372cc821:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.9062 | はい |
| `5f8daf53ef21:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `a0d1e6b47152:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.8906 | はい |
| `5f8daf53ef21:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `a0eb29beacb4:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.8906 | はい |
| `5f8daf53ef21:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `edb371be3967:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.9062 | はい |
| `8715bb53fad9:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `9a9d372cc821:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.8906 | はい |
| `8715bb53fad9:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `a0d1e6b47152:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.9375 | はい |
| `8715bb53fad9:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `a0eb29beacb4:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.8750 | はい |
| `8715bb53fad9:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `edb371be3967:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.8906 | はい |
| `9a9d372cc821:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `a0d1e6b47152:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.9219 | はい |
| `9a9d372cc821:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `a0eb29beacb4:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.9531 | はい |
| `9a9d372cc821:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `edb371be3967:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 1.0000 | はい |
| `a0d1e6b47152:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `a0eb29beacb4:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.9062 | はい |
| `a0d1e6b47152:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `edb371be3967:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.9219 | はい |
| `a0eb29beacb4:AnalyzeDeliveryOrPayload@reviewed_static_unit` | `edb371be3967:AnalyzeDeliveryOrPayload@reviewed_static_unit` | 0.9531 | はい |

## 制約

- 類似性はコード共有、共通library、compiler生成処理でも生じます。
- 類似性だけでファミリー、actor、campaignを確定しません。
- 異なるdecompiler設定や難読化によりfingerprintが変化する可能性があります。
