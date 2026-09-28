# 固定sourceのGit改行保持

## 目的と対象

managed resource／readerの起動前監査は、通常sourceのraw byte SHA-256と全AST契約を両方検査します。Gitの改行変換だけでもSHAが変わり、検証済み実装が拒否されるため、次の9fileだけをrootの`.gitattributes`で`-text diff`へ固定します。

```text
unpackers/managed_resources.py
unpackers/dnfile_resource_adapter.py
unpackers/clr_input_binding.py
unpackers/managed_resource_snapshot.py
unpackers/managed_constructor_guard.py
unpackers/managed_il_triage.py
unpackers/managed_proxy_deobfuscator.py
analysis-framework/common/dotnet_rat_config.py
unpackers/managed_metadata.py
```

`-text`はこの9fileのGit改行変換を停止する指定で、`diff`はtext差分の表示を維持します。全Python fileへ広げず、既存のRedLine profile用`eol=lf`規則も保持します。解析コード、source pin、全callee・receiver・context・深さの監査条件は変えません。[Git公式attributes仕様](https://git-scm.com/docs/gitattributes)

保存したCRを末尾空白と誤認しないため、同じ9fileだけに`whitespace=blank-at-eol,blank-at-eof,space-before-tab,cr-at-eol`を明示します。既定の空白検査3種類は維持し、CRだけを改行の一部として扱います。`-whitespace`や全体設定の変更は行いません。将来の別`core.whitespace`設定に追加された厳格ruleを自動継承する指定ではありません。[Git公式core.whitespace仕様](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corewhitespace)

## 修正前後の確認

修正前のworktreeでは、resource helper5fileとmetadata reader1fileはLF、consumer2fileとSettings reader1fileは混在改行でした。全9fileのraw SHAは現在のpinに一致していましたが、`core.autocrlf=true`のGit cleanを適用すると混在3fileの保存候補byteが変わりました。consumer2fileの既存indexがLFであることも確認しましたが、属性追加だけで既存indexを修復したとは扱いません。LF／CRLF版のASTが同じでも、raw SHA不一致を許可へ変換しません。

修正後は全9fileで次を確認しました。

- effective属性は`text=unset`、`diff=set`。`eol`、`filter`、`working-tree-encoding`は未指定。
- `git hash-object --path`と`git hash-object --no-filters`の保存候補OIDが一致。
- raw SHA-256は修正前から不変で、現在のsource pinに一致。
- production実装981fileのcommitmentも不変。解析コードと既存77test fileの編集は無し。

追加した包装回帰10件は2.99秒で成功しました。人工patchの`git apply --check`5対照でも、正常CRLFは受理し、CRLF直前のspace／tab、space-before-tab、追加の末尾空行を拒否しました。patchは適用せず、通常sourceとGit indexは変更していません。包装回帰は追加した別test fileであり、既存の77file回帰へ成功数を加算しません。

これは現worktreeにおける包装確認です。Git保存候補のOIDはsource pinのSHA-256とは別の検査であり、公開blob、別OS、fresh cloneでの実行成功を追加証明するものではありません。3,053回帰試験と全110handler／1051formatの成功は[最終固定版の検証](STATIC-AUTOMATION-IMPROVEMENTS-20260927.md#9月28日の最終固定版)として区別します。

## 公開時と残る境界

公開する際は、属性、9source、catalogのpinを同じ差分単位で監査します。既存の正規化済みindex／blobを採用せず、保存される9fileのbytesが検証済みraw SHAと一致することを別途確認してください。今回の包装修正でstaging、commit、push、PRは行っていません。

この指定は、優先される別attributes、追加filter、`working-tree-encoding`、editorや手動copyによる改行変換を包括的に防ぐものではありません。他の固定source pin全体の移植性も保証しません。改変sourceが拒否された場合、pin側の改行正規化や一般許可の拡大で救済せず、変更内容と全契約を改めて監査します。
