# Malware configuration extractors

`extractors/` は解析済みマルウェアの設定抽出を、解析engineやemulatorから独立して提供する。
検体を実行せず、外部通信も行わない。出力は全familyで共通のJSON契約を使用する。

## Supported families

| ID | 抽出対象 | 確定条件 |
|---|---|---|
| `valleyrat` | variant、endpoint、config/stage URL | 復号済みconfigがない文字列候補は`inferred` |
| `agenttesla` | FTP/SMTP/HTTP/Telegram/Discord候補 | credential値は出力せず、存在フラグだけを残す |
| `remcosrat` | family marker、endpoint候補 | encrypted/resource config未復元時は確定しない |
| `venomrat` | Quasar/xClient marker、endpoint候補 | marker相関があってもconfig参照までは`inferred` |
| `mx-go` | embedded JSON、control server | embedded JSON内の値は`confirmed`、secret-like fieldは除外 |

## Usage

```powershell
$env:PYTHONPATH = '<repo-root>'
python -m extractors.config_extractor `
  --family valleyrat `
  --input C:\malware-lab\quarantine\sample.bin `
  --output C:\malware-lab\output\config.json
```

入力は隔離領域の検体、復元済みpayload、または復号済みconfig artifactを想定する。公開結果へ
実行可能bytesやcredentialをコピーしない。

## Common output

- `family`, `sample_sha256`
- `config`: family固有だがpublish-safeな設定
- `findings`: kind、value、role、confidence、source
- `limitations`
- `credentials_published=false`
- `executed=false`, `network_contacted=false`

## Test and pydoc

```powershell
python -m pytest -q extractors/tests
```

生成済みAPI文書は `docs/pydoc/` を参照する。
