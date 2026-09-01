# Hatching Triage照合

## 結果

- 照合日時: `2026-08-31T23:14:22.723720Z`
- `domain:`検索: `9`件
- 完全URL検索: timeout `1`件
- archive／original／depumped／unpacked SHA-256検索: `0 / 1 / 0 / 0`件
- 公開一致: `0`件
- private一致: `3`件を公開成果物から除外
- 新規sample提出: `0`件
- sample、dumped file、memory、PCAP download: `0`件
- ローカル実行: `0`件

exact hash検索に一致があってもprivate sampleの内容は転記しない。公開済み解析との一致がないことは、
未解析・無害・後段なしを意味しない。raw command、private metadata、API keyも保存していない。

## 後段解析状態

提供archiveから得たoriginal、depumped、UPX-unpackedの3層はhashを固定し、
[canonical malware case](../../../../malware/unclassified/versions/unknown/cases/d3fc5ed15a97063e804664d5f379bb7454d103b4defa9ac9e788f1eaa922a675/README.md)
で静的解析した。sandbox artifactに依存せず、検体は実行していない。
