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

## 共通ZIP安全契約

通常ZIPとAES-ZIPは、どちらも common/malware_io.py の同じストリーム読み込み実装を通します。safe_extract_zip.py、extract_packages.py、extract_malwarebazaar_member.py、analyze_submission.py が個別に archive.read() する実装は使用しません。

読み込み開始前と読み込み中に、次を検証します。

- メンバー数、個別展開サイズ、総展開サイズ、圧縮率をすべて正の有限上限として扱う。
- 宣言サイズを超えた最初の1 byteで読み込みを停止し、偽装された中央ディレクトリサイズを拒否する。
- 絶対パス、drive指定、空要素、.、..、symlinkを拒否する。
- 大小文字だけが異なる重複名と、payload と payload/a.bin のようなファイル・ディレクトリ衝突を拒否する。
- 全メンバーと全出力先の検証が終わるまで永続化を開始しない。
- 既存ファイルは上書きせず、書き込み中の障害時はその呼び出しで作成したファイルを除去する。

通常ZIPは read_zip_members、受け入れ用パスワード付きZIPは read_aes_zip_members または read_single_aes_zip_member を使用します。保存が必要な明示的ワークフローだけが persist_archive_members を呼びます。通常の解析は復元byte列をメモリ内に保持します。

## 生ファイルと静的レイヤーの契約

read_file_capped は、stat の結果だけを信用せず、ストリーム読み込み中にも上限を検証します。ワンショット解析は archive_mode、max_file_size、max_files をプログラム呼び出し時にも検証し、bool を整数上限として受理しません。

静的レイヤーパイプラインは、raw入力についてSHA-256とsizeの一致を構築時に検証します。認証済みZIPメンバーでは、outer_sha256 と outer_size が外装アーカイブを示すため、内包byte列との一致を要求しません。unpackerの戻り値、空artifact、非bytes、過大artifact、重複artifactを個別に処理し、サニタイザー自身が失敗した場合も未加工のreportや例外文字列を公開成果物へ残しません。

## C2入力とHTTP成果物の契約

common/network_target.py を、C2候補、ライブ検査、Shodan検索式のhost・port・URL正規化に使用します。制御文字、曖昧なport、IDNA不正、IPv6 zone ID、無効IPv4、非公開・予約・文書用アドレスをfail-closedで扱います。

HTTPライブ検査では、Hostをauthority形式、pathを有界なorigin-formへ制限します。応答の Set-Cookie、Authorization、Proxy-Authorization、X-API-Key などは値を [REDACTED] へ置換し、秘匿したヘッダー名だけを redacted_headers へ記録します。リダイレクト追従や取得した内容の実行は行いません。

## 回帰テスト

主な安全境界は次のテストで固定します。

- tests/test_malware_io.py: ZIP種別共通のquota、サイズ偽装、重複、symlink、上書き、上限付きファイル読み込み。
- tests/test_safe_archive_extractors.py: 展開CLI、内包ZIP、再帰解析での全件事前検証。
- tests/test_static_layer_pipeline.py: 入力整合性、unpacker契約違反、サニタイザー失敗、空・重複artifact。
- tests/test_network_target.py、tests/test_c2_candidate_detector.py、tests/test_c2_detector.py: C2入力、検索式注入、HTTP request注入、資格情報秘匿。

実検体を使わず、合成byte列とloopback限定fixtureで正常系、異常系、境界値、安全性を検証します。
