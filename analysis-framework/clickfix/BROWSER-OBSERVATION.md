# ClickFix実ブラウザ観測

## 目的

静的GETだけでは復元できない、JavaScript実行後のClickFix表示、copy操作、clipboardへ設定される
PowerShell／cmd／WebDAV commandを安全に観測します。取得したcommandは解析対象であり、実行対象ではありません。

## 観測手順

1. 対象domainを事前にDNS解決し、private、loopback、link-local宛ての場合は接続を中止する。
2. 新しいブラウザtabを用い、最初のdocument scriptより前に`navigator.clipboard.writeText`、
   `ClipboardItem`、`document.execCommand("copy")`、copy eventをinterceptする。
3. clipboardへ渡される文字列を観測ログへ保存し、可能な限りnative clipboardへの転送を抑止する。
4. JavaScriptを有効にしてlanding pageを開き、visible text、title、最終URL、redirect、network request、
   fake CAPTCHA／verification表示を記録する。
5. copy、verify、I am not a robot等の表示上の操作を再現し、clipboard eventが発生するか確認する。
6. 取得commandは文字列として静的に分解し、process、LOLBIN、URL、WebDAV、dead-drop resolver、
   復号処理、次段取得・実行ロジックを記録する。貼り付けや実行はしない。
7. downloadが開始された場合はブラウザ内で開かず、URL、file名、応答metadataだけを記録する。
   検体取得が必要な場合は、既存の上限、hash確認、Git管理外保存を行う別工程へ渡す。
8. 成功・失敗を問わず、case別の`browser-observation.json`をGit管理外に保存する。

## 禁止事項

- 取得commandをRun dialog、terminal、PowerShell、cmd、`mshta`、`rundll32`等へ貼り付けない。
- 認証情報、個人情報、実在組織の情報を入力・送信しない。
- form送信、明示的POST、WebDAV変更系method、malware protocolを送信しない。
- downloadしたscript、DLL、PE、archiveをブラウザまたはローカル環境で開かない。
- browser profileのcookie、password、local storageを調査目的で読み出さない。

## private観測ファイル

保存先は次の形式です。

```text
.work/clickfix/<YYYY-MM-DD>/cases/<case-id>/browser-observation.json
```

最小形式は次のとおりです。`private_value`を含むためGitへ追加しません。

```json
{
  "schema_version": 1,
  "case_id": "20260803-example",
  "domain": "example.invalid",
  "observed_at_utc": "2026-08-03T00:00:00Z",
  "status": "ok",
  "policy": {
    "javascript_executed": true,
    "clipboard_intercepted": true,
    "native_clipboard_write_suppressed": true,
    "command_executed": false,
    "command_pasted": false,
    "credentials_sent": false,
    "form_submitted": false,
    "payload_opened": false
  },
  "page": {
    "title": "Verification",
    "final_url": "https://example.invalid/",
    "lure_markers": ["verify", "clipboard"]
  },
  "clipboard_events": [
    {
      "api": "navigator.clipboard.writeText",
      "private_value": "powershell ..."
    }
  ]
}
```

取り込み時に`private_value`のSHA-256、長さ、command系列、process候補を生成します。公開側の
`live-observation.json`と`analysis.json`には生commandを含めず、hashと正規化結果だけを残します。

## 完了判定

ClickFix一括調査は、選定した全caseについてブラウザ観測を試行し、次のいずれかを記録します。

- `ok`: ページを表示してJavaScript実行後の状態を確認した。
- `blocked`: challenge、geo-fence、認証、browser制御上の制約で先へ進めなかった。
- `unreachable`: DNS、TLS、HTTP等により到達できなかった。
- `error`: 観測処理が失敗した。理由と再試行方法を残す。

clipboard commandが取得できなかった場合も、copy操作の有無、interceptの成否、停止位置を記録し、
「commandなし」と「観測不能」を区別します。
