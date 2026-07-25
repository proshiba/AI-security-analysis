# HijackLoader 検出プロファイル誤分類監査

## 概要

2026年7月24日の Windows 検体バッチを92件まで解析した時点で、HijackLoader と判定された27件を再監査した。27件はいずれも HijackLoader 固有の根拠を持たない誤分類であり、短い `idat` と `esal` が別の識別子に部分一致したことが共通原因だった。

この監査では検体を実行しておらず、C2やその他の外部インフラストラクチャへの接続も行っていない。

## 監査結果

| 確認項目 | 結果 |
|---|---:|
| 監査時点の解析件数 | 92件 |
| HijackLoader と誤分類された件数 | 27件 |
| `idat` と `esal` の部分一致を含む件数 | 27件 |
| 既知SHA-256との一致 | 0件 |
| 復号済み設定の回収 | 0件 |
| HijackLoader固有挙動の確認 | 0件 |
| Go製PE | 23件 |
| ルートPE以外の回収レイヤー | 0件 |

全27件がルートPEだけを解析した結果であり、展開・復号による後続レイヤーは回収されていなかった。したがって、既知ハッシュ、復号済み設定、固有挙動のいずれにも裏付けられていない短い文字列の部分一致を、ファミリー判定まで昇格させたことが誤分類の原因である。

## 修正内容

検出プロファイルから短い `idat`、`esal` および汎用的な配布手法名である `ClickFix` をマーカーとして除外した。判定には `HijackLoader`、`IDAT Loader`、`module stomping`、`Heaven's Gate` などの高特異度phraseを2個以上要求する。

修正後の条件と判定方針は、[HijackLoader解析README](../../../../analysis-framework/malware/hijackloader/README.md)および[Windowsファミリー検出プロファイル](../../../../extractors/profiles/windows_family_profiles.json)を参照する。

## 回帰確認

旧条件で誤分類された27件をメモリ内で再検査し、HijackLoader判定が27件から0件へ減少することを確認した。また、関連する83件のテストがすべて成功した。

主な回帰テストは次のとおりである。

- [HijackLoader誤検知回帰テスト](../../../../analysis-framework/tests/test_hijackloader_false_positive.py)
- [プロファイル型ファミリー検出テスト](../../../../analysis-framework/tests/test_profiled_family_detector.py)
- [プロファイル由来ルール検証テスト](../../../../analysis-framework/tests/test_profile_family_detection_rules.py)

## 結論

短い部分文字列や配布手法名だけではHijackLoaderの根拠にならない。今後は、高特異度phraseの相関、既知ハッシュ、復号済み設定、回収レイヤー、固有挙動を区別して記録し、単独の弱い根拠をファミリー確定へ使用しない。
