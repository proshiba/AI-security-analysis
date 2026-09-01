# ClickFix配信上の特徴

- Zone.Identifierから完全な配布URLとdomainを確認した。
- password付き7z archiveとして`WMIsave.exe`を配布する。
- archiveとpayloadの完全SHA-256を確認した。
- 配布後のPEはzero padding、UPX、NativeAOTを組み合わせる。
- 誘導画面、clipboard command、生commandは取得されていない。
- 配信domainと後段API domainは別である。

後段PEの機能は[正規malware case](../../../../malware/unclassified/versions/unknown/cases/d3fc5ed15a97063e804664d5f379bb7454d103b4defa9ac9e788f1eaa922a675/FEATURES.md)を参照する。
