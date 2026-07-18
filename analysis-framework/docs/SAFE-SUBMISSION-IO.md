# 安全な提出物I/Oと一括処理ワークフロー

`common/malware_io.py` は、MalwareBazaarのAES-ZIP認証、アーカイブメンバーパスの検証、内側ハッシュ計算、スクリプト文字列のデコード、安全な出力名、JSON出力、静的解析の安全マーカーを扱う唯一の既定実装です。

## 設計ルール

- `extract_malwarebazaar_member.py` を明示的に呼び出さない限り、復号したバイト列はメモリ内に保持します。
- すべてのメンバー名について、絶対パス、ドライブ接頭辞、`..` によるパストラバーサルを検査します。
- 単一メンバー用ツールは `read_single_aes_zip_member`、汎用トリアージは `read_aes_zip_members` を使用します。
- UTF-8／Windows-1252へフォールバックする前に、BOMまたはNULバイト分布からUTF-16を選択します。
- JSON証拠の末尾には `executed=false` と `network_contacted=false` を記録します。
- ファミリー検出器は `detector_support.py` を共有します。無関係な検出器の失敗によって後続検出器を止めてはなりません。

## 一括処理の全実行順

`Invoke-FamilyBatch.ps1` は次の段階を実行します。

1. 認証付き汎用トリアージと内側SHA-256の完全一致確認
2. ファミリー／キャンペーン分類
3. スクリプトの場合は、エンコード層解析、ロジック抽出、Base64テキスト抽出
4. VBSの場合は、シンクを起点とする変数追跡
5. Unicode／画像段階キャンペーンの場合は、マーカー除去と連結文字列の再構築
6. ISO／IMGの場合は、マウントしないISO9660インベントリ
7. 完了段階と安全マーカーを含む `batch-run-summary.json`

既定のPython経路では、RARはインベントリ作成だけを行います。レビュー済み外部抽出器を別途使用できますが、引き継ぐ結果には内側SHA-256の完全一致が必要です。

## 失敗時の確認

- `cannot authenticate/decrypt archive`: アーカイブ、パスワード、`pyzipper` を確認し、認証を迂回しないでください。
- `expected one file member`: 汎用トリアージを使用するか、レビュー済み複数メンバーハンドラーを追加してください。
- `member exceeds ...`: 宣言サイズを確認し、レビュー済みケースだけで上限を引き上げてください。
- `unsafe archive member path`: アーカイブを隔離し、パスを正規化して抽出しないでください。
- `campaign unknown`: 汎用トリアージ後に停止し、レビュー済み構造ハンドラーを追加してください。
- `validate_batch_outputs.py` で段階が不足: 公開前に `batch-run-summary.json` と段階固有JSONを確認してください。
