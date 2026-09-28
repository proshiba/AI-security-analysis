# CLR構築前の宣言検査

この文書は通常sourceへ採用した構築前検査の範囲を説明する。検体の実行やC2への接続は追加しない。人工試験の成功を実検体の設定抽出率や解析完了と混同しない。

## 何を防ぐか

metadata parserを構築してからrow数を制限すると、その構築時点で過大な宣言に応じた割り当てが生じ得る。`managed_constructor_guard.py`は原本bytesだけからPE、CLI、metadata streamと全45tableの宣言を検査し、固定2consumerの`dnfile.dnPE`より前に拒否する。

| 項目 | 固定上限 | 範囲 |
|---|---:|---|
| 原本入力 | 512 MiB | exact `bytes`の受付 |
| table行数 | 個別20,000、全体80,000 | 全45tableの宣言 |
| section | 96 | raw／virtual範囲の検証 |
| callerによる上限変更 | 引下げのみ | boolean、0、負値、固定上限超過は拒否 |

構築前の全45table宣言と、構築後の固定13table共有snapshotは別の検証である。前者はtableを構築してよい宣言範囲、後者は同じ入力・parser・row・heapに結び付けた消費結果を扱う。構築前の`accepted=true`だけで、rowの意味、resource本文、C2設定、終端payloadを確認済みにしない。

## canonical配置に限定する理由

parserが不整列のraw pointerやVirtualAddressを補正すると、独自のraw検査と異なる場所を読む可能性がある。検査後に差を発見してpartialへ戻すだけでは、構築前の予算は守れない。このためFileAlignment、SectionAlignment、SizeOfHeaders、sectionの位置とraw／virtual重複についてcanonicalな範囲だけを受理する。

low-alignment、header alias、補正を要する非整列、raw／virtual重複、未知stream、非canonical table layoutを推測で救済しない。これらは固定理由の`partial`であり、マルウェアでないことを意味しない。別の静的解析手段が必要な未対応入力として扱う。

## 通常入口と起動前監査

対象はtriageとproxyの固定2consumerである。exact bytes検査、構築前guard、partial時の直接return、parser構築、入力に結び付いた共有snapshotの順序を起動前AST監査でも確認する。

source SHA-256だけでは許可しない。固定guardの全callee本文、import元、receiver、namespace、callshape、entry重複、再代入を照合する。重複entryの先定義がbody呼出しを持たない場合も、file登録時の拒否側predicateを必ず適用する。汎用reflectionや任意allocatorの許可は増やさない。

## 保証しないこと

- 全repositoryのparser入口へ適用した仕組みではない。
- parser全体のheapコピー、native directory解析、CPU、allocation、wall clockを一律保証しない。
- metadata行の高水準意味、method本文、runtime dispatch、framework真正性を確認しない。
- カウンタは宣言の件数であり、CPU訪問や全parser処理を一括予約した数ではない。
- 原本、resource本文、heap文字列、token、offset、鍵をcoverageへ追加公開しない。
- 実検体に対する設定抽出率や未知検体の成功率を保証しない。

## 人工試験と記録

原本とparserの写像対照は最大2行の人工PEで行う。大量row割り当て、実検体、OS binary、CIL／CLR実行、外部通信を使わない。通常sourceへ採用した後の試験は、private候補版の結果と分離して追記する。失敗した旧版・反例も保存し、新成功数へ置き換えない。


通常配置の宣言予算149件、canonical配置29件、独立した写像対照33件に、既存triageと固定API生成の回帰を合わせた234件は7.35秒で成功した。短い壊れたPEがparser例外へ進む旧期待値1件は、構築前拒否の検証へ変更した。parser例外と非managed結果の検証自体は正常構造の人工PEで維持している。起動前依存監査の通常回帰と全体coverageは別に確認する。
