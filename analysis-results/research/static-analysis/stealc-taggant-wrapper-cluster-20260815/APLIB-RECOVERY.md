# StealC保護外層のaPLib追加静的解析

## 対象と結論

2026年8月15日に同一保護外層clusterへ相関した11件を、exact SHA-256で再取得・照合し、検体を実行せずに追加解析した。従来は`.taggant`入口と7 section構造までの確認だったが、今回は全件で次の2段階を静的に復元できた。

1. 小型ランダム実行sectionが、主暗号化sectionの先頭4,096 byteをlittle-endian dword単位でXORした後に加算する。
2. 復号page内のloaderが、主section先頭から`0x212`のaPLib streamを疎な実行sectionの先頭から`0x14`へ展開する。

全11件で復元は成功し、aPLib入力の消費量は1,648,805～1,716,201 byte、展開量は2,677,127～2,793,553 byteだった。検体ごとの鍵、RVA、page SHA-256、展開結果SHA-256、entry fingerprintは[aplib-recovery.json](aplib-recovery.json)に記録した。生の復号pageや展開byte列は公開していない。

## 共通する処理鎖

```text
.taggant entry
  -> 小型ランダム実行section
  -> 先頭4 KiBのXOR＋加算復号
  -> aPLib decoder
  -> 2.68～2.79 MiBの位置独立loader領域
  -> call/pop基準取得とregister退避
  -> 0x80 byte単位の変換処理
  -> 0x7000 byteのruntime mutation loop
  -> 未復元のThemida内層
```

展開領域の先頭は全件でnear jumpになり、その遷移先の先頭16 mnemonicは`mov, mov, pushal, call, pop, sub, mov, mov, mov, mov, mov, mov, test, je, mov, add`で一致した。全件に`%userappdata%\RestartApp.exe`が存在する一方、厳密な`MZ`／`PE\0\0`対応を満たす埋込PEは0件だった。

## C2と終端payloadの判定

- 展開領域内に有効なURL、domain、StealC C2候補は確認できなかった。
- 短いURL様ASCII断片は存在したが、いずれもランダムな命令・data領域の偶発一致で、hostやpathとして成立しない。
- runtime mutationより内側の終端PE、検体固有config、C2は復元していない。
- `09034743…`で別の公開unpack証拠から復元済みのStealC v1 config／historical C2は独立証拠であり、このaPLib展開領域から直接得た値として扱わない。

残るblockerは`expanded_themida_runtime_mutation_layer_unresolved`である。次の解析では、0x7000 byte変換後の命令領域を静的に再構成し、終端PEと親検体のexact byte lineageを証明する必要がある。

## 自動復元器

[taggant_aplib_recovery.py](../../../../analysis-framework/malware/stealc/taggant_aplib_recovery.py)は、11件のexact SHA-256、PE32／7 section配置、暗号化page SHA-256、復号page SHA-256、aPLib消費量、展開量・SHA-256、entry window SHA-256、永続化marker位置をすべて照合する。1項目でも異なる場合はfail-closedで拒否する。

```powershell
py -3.13 .\analysis-framework\malware\stealc\taggant_aplib_recovery.py `
  --input C:\malware-lab\sample.quarantine.exe `
  --output C:\malware-lab\stealc-aplib-recovery.json
```

出力はhash、size、RVA、鍵、marker、状態だけで、復号byte列を含まない。aPLibは入力境界、参照offset、gamma値、8 MiBの出力上限を検査する独自の有界実装であり、検体コードやCPU emulatorを実行しない。合成回帰試験は[test_stealc_taggant_aplib_recovery.py](../../../../analysis-framework/tests/test_stealc_taggant_aplib_recovery.py)にある。

## 安全境界

- 検体・復号領域・展開領域の実行：なし
- CPU emulation：なし
- 外部host／C2への通信：なし
- raw payloadのrepository保存・公開：なし
- 公開結果：決定的なscalar metadataとSHA-256のみ
