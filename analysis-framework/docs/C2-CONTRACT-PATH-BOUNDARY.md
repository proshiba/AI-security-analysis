# C2解析契約内のファイル参照の境界

`c2_analysis_contract.py`は、契約JSON内の`automation.handlers`と`automation.tests`を、callerが選択したrepository内の通常fileとして確認します。この参照確認は検体を開かず、C2やdead-dropへ接続しません。

## 前提

repositoryは、絶対かつcanonicalなlocal rootです。rootに至る親componentはcallerの信頼境界にあり、非reparseであることを前提にします。契約JSONからrootを選ばせません。`repository=None`では従来どおりfile参照の確認を省きます。

## 解決前の拒否

- 不正型、empty、NUL、4096文字超、128component超。
- UNC、device／extended namespace、外部absolute、Windows drive-relative／root-relative、prefixが似ているだけの別root。
- 途中でrepository外へ抜ける`..`。脱出後に戻る参照も拒否します。
- Windows componentのDOS device名、末尾dot／space、ADS colon、wildcard、禁止文字と制御文字。

同値な別名へ書き換えて救済せず、これらはfilesystem lookup前に拒否します。通常relative、contained absolute、普通のdirectoryを通る`a/../b`は維持します。

## 非追従確認と失敗処理

rootと各componentを`lstat()`で検査し、symlink／Windows reparseを拒否します。`a/../b`の`a`も、`..`を消す前に検査します。途中componentがfileの場合やmissing／unreadableの場合も拒否します。

全componentの確認後にだけ`resolve()`を行い、解決後の包含性も再確認します。metadata確認、解決、`is_file()`の`OSError`・`ValueError`・`RuntimeError`は、既存のpath findingへ正規化します。例外停止や正常完了、日次繰越への昇格を行いません。

正常な未完了契約は、他の必要条件を満たせば従来どおり`daily_ready=True`、`complete=False`、`deferred=True`です。参照不正は繰越可能な未解析理由とは別です。

## 保証しないこと

このPathベースの検査は、敵対的な同時filesystem変更に対する強いTOCTOU保証やsandboxではありません。検査後の差替えを完全に防ぐhandle-basedな設計は別途必要です。rootの親が信頼できない場合、任意Python object／Path subclass、JSON reader全体の有界化もこの改善の対象外です。

## 人工試験

私有候補の80件と独立追加33件は113件すべて成功しました。試験は人工`lstat`／`resolve`／`is_file` sentinelと正常local tempfileだけを使い、実UNC、外部通信、実case、検体は使用していません。通常配置のパス試験79件を含む契約・公開処理・履歴集計の319件も80.33秒で成功しました。両suiteの重複を独立検体数へ合算しません。
