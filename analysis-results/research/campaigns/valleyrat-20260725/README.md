# ValleyRAT campaign帰属試行

## 結論

canonical case `68`件を公開OSINTと照合しました。 公開campaignのhash完全一致は`0`件です。
完全一致しない検体を既知actorへ押し込まず、ローカルで親子関係または固有構成が確認済みのものだけをcampaign候補へ分けました。

## 分類結果

| 状態 | 件数 | 意味 |
|---|---:|---|
| 公開campaign完全一致 | 0 | 公開SHA-256またはMD5との完全一致 |
| ローカルcampaign候補 | 6 | 親子hashまたは固有の配布chainをレビュー済み |
| コードcluster候補のみ | 9 | imphash完全一致。campaign確定ではない |
| 未解決 | 53 | 帰属に足る強い共有証拠なし |

詳細は[全case一覧](CASES.md)、[公開OSINT campaign照合](OSINT-CAMPAIGNS.md)、[判定規則](rules/README.md)を参照してください。

## 重要な解釈

- 既存の`campaign_type`は解析handlerを選ぶ配布・構造分類であり、攻撃campaign名ではありません。
- MalwareBazaarの`SilverFox`はcommunity tagとして保持しますが、actor帰属には使用しません。
- ValleyRAT builderが広く利用可能であるため、ValleyRAT検出だけでSilver Fox、TA4922、その他のactorを決めません。
- imphash一致はコード近縁性の手掛かりです。同一operator、同一配布、同一期間を意味しません。

## ローカルcandidate cluster

- [偽Yuanbao side-loading chain](local-candidates/local-valleyrat-yuanbao-sideload/README.md): 2件、確度`高`
- [税務通知ISO・NVML side-loading chain](local-candidates/local-valleyrat-tax-iso-nvml/README.md): 2件、確度`高`
- [MSI・LZX CAB・保護PE配布cluster](local-candidates/local-valleyrat-msi-lzx-protected-pe/README.md): 2件、確度`中`

## 安全性

この処理は既存の公開済み解析成果物とOSINT registryだけを読みます。検体実行、C2接続、外部サービスへの検体送信は行いません。
