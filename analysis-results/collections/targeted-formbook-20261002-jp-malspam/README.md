# 2026-10-02 FormBook／XLoader系 日本語名WSF解析

ユーザー提供の`261002-fldpqsw15r_pw_infected.zip`を、検体を実行せず静的解析しました。WSFからPowerShell、GHOSTED managed loader、x86 FormBook/XLoader payloadまで復元しています。

- case: [解析結果](../../malware/formbook/versions/unknown/cases/0eb380a4609662b66d946d0991e810aa47b80dc3733aee4e59cfba1bd1107ce7/README.md)
- Triage公開解析: [261002-fldpqsw15r](https://tria.ge/261002-fldpqsw15r)
- family: FormBook/XLoader
- C2候補: HTTP 15件、DNSのみ1件
- live C2確認: 未実施
- 現在のblocker: 現在検体固有の第2層C2鍵計画と16 record selector対応

外部通信は、WSFへ埋め込まれたstage URLの1回限定取得とTriage公開成果物取得だけです。検体本体、復号payload、memory dumpはリポジトリへ保存していません。
