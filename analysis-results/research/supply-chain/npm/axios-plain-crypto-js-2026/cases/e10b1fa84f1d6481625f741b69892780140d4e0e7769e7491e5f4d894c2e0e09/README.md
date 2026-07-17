# axios / plain-crypto-js 供給網侵害

## 判定

復元した `setup.js`（SHA-256: `e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09`）は、`plain-crypto-js@4.2.1` を通じてインストールされる、確認済みの複数環境対応ダウンローダーである。この依存関係は、悪性の `axios@1.14.1` および `axios@0.30.4` リリースへ注入された。最終的にダウンロードされるペイロードは公開情報で遠隔操作型トロイと説明されているが、各環境向けペイロードを復元できなかったため、本書ではファミリーを割り当てない。

## 静的な難読化解除

`stq[]` の値を逆順にし、`_` を Base64 のパディングへ戻して UTF-8 として復号した後、文字コードを `Number()` で正規化した `OrDeR_7077` および10進数333と排他的論理和する。抽出器は JavaScript の `NaN -> 0` というビット演算時の型変換を模擬し、Node.js を呼び出さない。

確認済みの出力:

- C2／ペイロード接続先: `http://sfrclak.com:8000/6202033`
- 基点の接続先: `http://sfrclak.com:8000/`
- 報告された A レコード: `142.11.206.73`
- キャンペーン／パス識別子: `6202033`
- macOS の送信マーカー: `packages.npm.org/product0`
- Windows の送信マーカー: `packages.npm.org/product1`
- Linux の送信マーカー: `packages.npm.org/product2`

## 環境別の挙動

| 環境 | 挙動 |
|---|---|
| macOS | 一時ディレクトリ配下にアップルスクリプトを書き込み、環境別マーカーを送信し、`/Library/Caches/com.apple.act.mond` へ保存する。実行権限を付与し、Zシェルで起動する |
| Windows | PowerShell を `%PROGRAMDATA%\wt.exe` へコピーし、`%TEMP%\6202033.vbs` と `.ps1` を書き込む。実行ポリシーを回避して非表示で起動した後、一時スクリプトを削除する |
| Linux／その他 | product2 を送信し、`/tmp/ld.py` へ保存して、`python3` を `nohup` 配下で起動する |

環境別処理の後、`setup.js` と `package.json` を削除し、`package.md` を `package.json` へ改名することで、無害な版4.2.0を偽装する。そのため、実行後にインストール済みの版だけを確認する方法では不十分である。ロックファイル、npm キャッシュ、継続的インテグレーションのログ、および `plain-crypto-js` の存在履歴が、より強い根拠となる。

## 供給網侵害の IOC

| 生成物 | 値 |
|---|---|
| axios 1.14.1 npm shasum | `2553649f2322049666871cea80a5d0d6adc700ca` |
| axios 0.30.4 npm shasum | `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71` |
| plain-crypto-js 4.2.1 npm shasum | `07d889e2dadce6f3910dcbc253317d28ca61c766` |
| setup.js SHA-256 | `e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09` |

## 検出評価

- **誤検出リスク低**: setup.js の完全一致ハッシュ、当該パッケージ配下の `plain-crypto-js` 依存関係、または環境別マーカーを本文に含む完全パスへの外向き送信。
- **中程度**: パワーシェルから `%PROGRAMDATA%\wt.exe` を作成したうえでの、スクリプト実行または転送ツールの動作。管理者が正当にインタープリターをコピーまたは改名する場合はあるが、チェーン全体はまれである。
- **高い**: 一般的な `postinstall`、転送ツール、パワーシェル、アップルスクリプト実行ツール、パイソンの個別実行。

生成物: [復号済み設定](config.json)、[IOC](iocs.json)、[YARA](rules/npm_axios_supply_chain.yar)、[Sigma](rules/npm_axios_windows.yml)。

## 制約

MalwareBazaar から取得して静的に復号できたのは `setup.js` だけである。削除済みの npm tarball と第2段階ペイロードは入手できなかった。C2 へは接続していないため、現在の稼働状況と応答内容は未確認である。
