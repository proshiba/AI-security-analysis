# 公開OSINT campaign照合

hash完全一致を最優先しました。network、lure、配布方式だけの類似は確定扱いにしません。

| campaign | 期間 | 報告actor | 完全一致case |
|---|---|---|---:|
| `proofpoint-2023-chinese-invoice-resume` / 2023年 中国語請求書・履歴書メールcampaign | 2023-03から2023-06 | 未帰属 | 0 |
| `zscaler-2024-multistage` / 2024年 ThreatLabz多段loader campaign | 2024 | 中国拠点の脅威group（報告表現） | 0 |
| `fortinet-2024-chinese-speaker` / 2024年 中国語話者標的多段campaign | 2024 | Silver Fox（Fortinetによる疑い） | 0 |
| `itochuci-2025q4-2026q1-japanese-malspam` / 2025年Q4から2026年Q1 日本語malspam campaign群 | 2025-12から2026-03 | 未帰属 | 0 |
| `darklab-2025-2026-dual-pronged` / Silver Fox二方向配布campaign | 2025から2026 | Silver Fox（Dark Labによる帰属） | 0 |
| `k7-2026-fake-teams` / 2026年 偽Microsoft Teams NSIS campaign | 2026 | Silver Fox（K7による帰属） | 0 |
| `c1bas-2026-whatsapp-india` / 2026年 WhatsApp・インド組織標的campaign | 2026-03 | Silver Foxの疑い（C1BASによる評価） | 0 |

## 参照資料

- [原題: Chinese Malware Appears in Earnest Across Cybercrime Threat Landscape](https://www.proofpoint.com/au/blog/threat-insight/chinese-malware-appears-earnest-across-cybercrime-threat-landscape)
- [原題: TA4922: A Suspected Chinese Crime Group Going Global](https://www.proofpoint.com/us/blog/threat-insight/ta4922-suspected-chinese-crime-group-going-global)
- [原題: New Updates to ValleyRAT](https://www.zscaler.com/mx/blogs/security-research/technical-analysis-latest-variant-valleyrat)
- [原題: A Deep Dive into a New ValleyRAT Campaign Targeting Chinese Speakers](https://www.fortinet.com/blog/threat-research/valleyrat-campaign-targeting-chinese-speakers)
- [原題: Cracking ValleyRAT: From Builder Secrets to Kernel Rootkits](https://research.checkpoint.com/2025/cracking-valleyrat-from-builder-secrets-to-kernel-rootkits/)
- [原題: Observations of Japanese Malspam in 2026 Q1: Analysis of Emails Delivering ValleyRAT](https://blog-en.itochuci.co.jp/entry/2026/04/28/170000)
- [原題: An Analysis of ValleyRAT Infection Campaigns from Fake Installers, Japanese Malicious Emails](https://www.levelblue.com/blogs/spiderlabs-blog/an-analysis-of-valleyrat-infection-campaigns-from-fake-installers-japanese-malicious-emails)
- [原題: Silver Fox’s Dual-Pronged Strategy: Dissecting the ValleyRAT Distribution Campaign](https://blog.darklab.hk/tag/trojanised-installer/)
- [原題: Fake Microsoft Teams Campaign Delivers ValleyRAT via NSIS Installer and DLL Sideloading](https://labs.k7computing.com/index.php/fake-microsoft-teams-campaign-delivers-valleyrat-via-nsis-installer-and-dll-sideloading/)
- [原題: Tracking a Suspected SilverFox APT Operation](https://www.c1bas.com/blog/silverfox-apt-valleyrat-python-infostealer)

## 帰属上の注意

Proofpointは2023年のValleyRAT活動を複数の異なる活動集合として扱っています。ITOCHU C&Iも日本語malspamの攻撃者属性を確定していません。Check PointとLevelBlueの調査が示すbuilder流通も考慮し、family一致をactor一致へ昇格させません。
