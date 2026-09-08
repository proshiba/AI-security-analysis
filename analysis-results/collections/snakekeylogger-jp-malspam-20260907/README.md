# 日本語マルスパム経由VIPKeyLogger収録（2026-09-07）

日本語名のJScriptから固定PowerShell、SHEEP process-hollowing loader、`VIPKeyLogger 4.4` terminalまで静的に復元した1件を収録します。

## 状態

- case: `d97dae8f8aafa75dd7c13e3b3018cbb3667bb8d990bd4fac1aee54ad492a51e6`
- 内部静的確認済みfamily: `snakekeylogger` / variant `vipkeylogger`
- terminal: `895b27dfc33644c7d8e7d9e3c216f7d278a892f45cd083a996720613a35b574d`
- sample execution: なし
- C2 contact: なし
- fixed stage retrieval: 1回
- remaining: SMTP liveness/authenticationのみ

## 主要結論

JScriptはhidden PowerShellを起動し、managed loaderが `aspnet_compiler.exe` をprocess hollowingします。terminalではbrowser/mail credential収集、初回Passwords/Cookies/AutoFill送信path、10分ごとのpassword senderを確認しました。keylogger等のcodeは存在しますが、今回buildのreachable pathとは分離しています。

## 成果物

- [case README](../../malware/snakekeylogger/versions/unknown/cases/d97dae8f8aafa75dd7c13e3b3018cbb3667bb8d990bd4fac1aee54ad492a51e6/README.md)
- [process behavior](../../malware/snakekeylogger/versions/unknown/cases/d97dae8f8aafa75dd7c13e3b3018cbb3667bb8d990bd4fac1aee54ad492a51e6/PROCESS-BEHAVIOR.md)
- [C2 analysis](../../malware/snakekeylogger/versions/unknown/cases/d97dae8f8aafa75dd7c13e3b3018cbb3667bb8d990bd4fac1aee54ad492a51e6/C2-ANALYSIS.md)
- [IOC list](../../malware/snakekeylogger/versions/unknown/cases/d97dae8f8aafa75dd7c13e3b3018cbb3667bb8d990bd4fac1aee54ad492a51e6/IOC-LIST.md)
