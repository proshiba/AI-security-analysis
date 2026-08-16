# 2026-08-16 Vidar提供元候補の追加静的確認

## 目的

MalwareBazaarが`Vidar`として報告した最新5件を、内部の静的根拠で再評価した。検体実行、外部通信、live C2 probeは行っていない。

## 結果

`3b8e7ffd...e1105e86`だけでVidar固有の反復XOR設定schema、version `3.0`、build ID、3件のdead-drop recordを確認した。この検体は[正規case](../../../malware/vidar/versions/unknown/cases/3b8e7ffdd1469728a242a7b86bb168486dc2b7258b03aa15c52df604e1105e86/README.md)として公開した。

残る4件は署名済みの難読化Go x64 PEであり、各検体に異なるrandomized main symbolが存在した。しかし、同じ静的確認ではVidar固有設定、Vidar固有record schema、復元child、最終C2を確認できなかった。提供元signatureだけでfamilyを確定せず、正規Vidar caseへ昇格していない。

| SHA-256 | size | first seen | 署名subject | 内部判定 |
|---|---:|---|---|---|
| `79399d2ccde8a358e1f62b9422e4ba4d337d14b293f0d351b5f611549188cf19` | 3,612,680 | 2026-08-15 16:26:22 | `NexaPulse Solutions` | Vidar未確認 |
| `c713bb386cb58f4e69960add340c8597fad9989cfb00a6bcfe2f4767dbf1cfc4` | 3,767,304 | 2026-08-15 16:15:11 | `NexaForge Solutions` | Vidar未確認 |
| `574b25e2d65712a885dd877d89d73e446104db074c63ec5d8c8af3583bf83956` | 3,383,824 | 2026-08-15 11:48:04 | `NexusBridge Technologies` | Vidar未確認 |
| `4395c75e4e288387972513b9760f6c868e6b2c2da417c723c24bcf32f11d69fd` | 3,808,848 | 2026-08-15 09:02:36 | `NexaForge Solutions` | Vidar未確認 |

## 判定境界

- code signingのsubjectは署名情報であり、malware familyやactorを単独では証明しない。
- MalwareBazaarのsignatureとtagは提供元報告として保持し、内部のattributionとは分離する。
- Go runtimeやrandomized symbolは一般的構造であり、Vidar固有根拠ではない。
- 後続でVidar固有設定またはchildが回収できた場合だけ、正規case化を再評価する。

## 安全性

- 5件とも実行していない。
- provider取得以外の外部通信を行っていない。
- binary、archive、鍵、復号payloadをrepositoryへ含めていない。
- repository外解析データは検体ごとに分離してS3へ保管する。
