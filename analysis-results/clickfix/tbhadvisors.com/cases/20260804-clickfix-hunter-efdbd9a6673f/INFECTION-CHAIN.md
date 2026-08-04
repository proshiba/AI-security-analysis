# 感染チェーン

## 到達状況

- 結果: `CF-07`で停止
- 終端payloadまで完了: `no`
- 次の解析: 次段URL、Triage artifact、memory／dumpから終端payloadを取得する。

## 段階図

```mermaid
flowchart LR
  CF01["CF-01: 配布・侵害ページへの到達\nobserved"]
  CF02["CF-02: fake CAPTCHA／verification表示\nobserved"]
  CF03["CF-03: clipboardへのcommand設定\nprovider_reported"]
  CF04["CF-04: 利用者による貼り付け・実行\nnot_observed"]
  CF05["CF-05: shell／LOLBINによる後続処理\nrecovered"]
  CF06["CF-06: resolver／次段取得\nrecovered"]
  CF07["CF-07: 終端payload／malware\nnot_retrieved"]
  CF01 --> CF02
  CF02 --> CF03
  CF03 -.未解決.-> CF04
  CF04 --> CF05
  CF05 --> CF06
  CF06 -.未解決.-> CF07
```

実線は観測、情報源報告、または静的復元で支持されたedgeです。点線は未観測・未取得です。
利用者がcommandを実行した事実は、このcase固有のsandbox証跡がない限り観測済みとしません。

## 段階別根拠

| Phase | 処理 | 状態 | 確度 | 根拠 |
|---|---|---|---|---|
| `CF-01` | 配布・侵害ページへの到達 | `observed` | `high` | 実ブラウザでJavaScript実行後のページ状態を確認 |
| `CF-02` | fake CAPTCHA／verification表示 | `observed` | `medium` | ライブ本文またはブラウザDOMでlure markerを確認 |
| `CF-03` | clipboardへのcommand設定 | `provider_reported` | `high` | 情報源がclipboard commandを提示 |
| `CF-04` | 利用者による貼り付け・実行 | `not_observed` | `unresolved` | 安全上再現しておらず、sandbox等の実行証跡もこの工程では未統合 |
| `CF-05` | shell／LOLBINによる後続処理 | `recovered` | `high` | command SHA-256 d2bf03344bcc740adb870c21a0c531478ad173e1a13ddcc1994eb258f081aaf1を静的解析<br>command系列 telegram_dead_drop_powershell<br>process候補: powershell.exe |
| `CF-06` | resolver／次段取得 | `recovered` | `medium` | commandから次段URLを1件復元 |
| `CF-07` | 終端payload／malware | `not_retrieved` | `high` | 終端payloadを取得できず |

## プロセスチェーン

`powershell.exe`

## 復元した次段URL

- `https://t.me/<redacted>`

## 判定上の注意

- ClickFix／ClearFake tagだけで終端malware、campaign、actorを補完しません。
- landing、payload取得先、dead-drop resolver、終端C2を役割別に扱います。
- ペイロード未取得でも、到達済みphaseと停止位置を残し、次回調査へ引き継ぎます。
