# 静的解析CLIのprivate失敗位置診断

`analyze_sample.py`がfatalで停止した場合、既存の`analysis-run-outcome.json`、`partial-summary.json`に加え、保存可能なprivate出力では`analysis-failure-diagnostic.private.json`を補助生成する。

既存のoutcome schema、`reason_code`、終了code、case seal、完了条件、runner validatorは変更しない。この診断は成功の根拠ではなく、`invalid_analysis_state`などで停止したコード位置を絞るためだけに使う。過去の封印済み成果物は書き換えず、改善後の検証は新jobで行う。

## 保存する情報

- allowlist内の例外型。独自型や未知型は`OtherException`にする。
- 実在する通常fileとして確認できたリポジトリ内componentの相対path。
- 固定allowlist内の関数名。その他は`unknown`にする。
- 有界の行番号。
- 最大16 frame、最大128 frame走査の切捨て状態。

リポジトリ外、存在しないfile、相対path、reparse経由、許可source領域外のframeは、component／関数を`unknown`、行を`null`にする。絶対pathのhashを照合用に残すこともしない。

例外message、`args`、locals、入力値、コード本文、source行、URL、query、credentialは参照・保存しない。型名や関数名も例外由来文字列をそのまま受理せず、固定allowlistへ制限する。

## 保存境界と失敗時の扱い

このsidecarはリポジトリ内の出力先には保存しない。workerから受け取る場合も完全一致schema、有界size、frame形式を検証し、不正な補助診断は無視する。診断生成、検証、保存の失敗によって元fatal、reason、終了codeを変更しない。

診断はprivateの解析運用データであり、公開case、UI、GitHubへcopyしない。非公開成果物の保管は既存datastore運用に従う。正常またはpartial終端として受理できるCLI終了時は、古いfatal／partial診断と併せてこのsidecarも安全に回収する。

## 合成試験

```powershell
py -3.13 -m pytest -q `
  analysis-framework/tests/test_sanitized_failure_diagnostic.py `
  analysis-framework/tests/test_analyze_sample_failure_artifacts.py
```

実検体は使用せず、秘密URL、query、token、local pathを含む無害な例外で非漏えい、未知frame、worker転送、malformed診断、旧schema保持、正常時cleanupを確認する。
