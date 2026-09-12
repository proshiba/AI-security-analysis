# NVML APC・Winos日本語malspam cluster

- ID: `local-valleyrat-nvml-apc-winos`
- 分類: `local_campaign_candidate`
- 確度: `高`
- actor: `未帰属`

## 根拠

- 正規NVIDIA side-load hostのSHA-256完全一致
- 悪性NVML proxy DLLのimphash、9つのNVML export、DAT復号、QueueUserAPC構造の一致
- Crypto\RuntimeBroker配置、RunOnce永続化、primary C2 192.252.180.45:6666の一致

## 検体

- [`93df03d7db7df23317ee87ebe3946ddff4364e45de5217b0c90c7925b22c8f04`](../../../../analysis-results/malware/valleyrat/versions/unknown/cases/93df03d7db7df23317ee87ebe3946ddff4364e45de5217b0c90c7925b22c8f04/README.md) — 観測名: 観測ファイル名なし
- [`6469edd613ceb62dd8e14a75628a6b75fa443ef4311da2b45e805bc7d18afe25`](../../../../analysis-results/malware/valleyrat/versions/unknown/cases/6469edd613ceb62dd8e14a75628a6b75fa443ef4311da2b45e805bc7d18afe25/README.md) — 観測名: 観測ファイル名なし

このcluster名はローカル解析用です。公開actorまたは既知campaignへの帰属を意味しません。
