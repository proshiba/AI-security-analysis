# Analysis framework

隍・焚縺ｮ繝槭Ν繧ｦ繧ｧ繧｢遞ｮ縺ｫ蟇ｾ蠢懊☆繧玖ｧ｣譫先ｩ溯・縺ｧ縺吶ＡInvoke-Analysis.ps1` 縺悟・騾夊ｭ伜挨蝎ｨ繧貞ｮ溯｡後＠縲～malware_type` 縺ｨ `campaign_type` 縺ｫ蟇ｾ蠢懊☆繧・handler 縺ｸ蜃ｦ逅・ｒ貂｡縺励∪縺吶・
```text
common/                    # ZIP螳牙・螻暮幕縲；hidra騾｣謳ｺ縺ｪ縺ｩ
classifiers/               # family/campaign隴伜挨
registry/                  # malware type縺ｨcampaign縺ｮ逋ｻ骭ｲ
malware/<type>/
  common/                  # type蜀・・騾壼・逅・  campaigns/<campaign>/    # 諢滓沒繝√ぉ繝ｼ繝ｳ蛻･handler
  config/                  # profile/evidence metadata
  docs/
  tests/
```

ValleyRAT蝗ｺ譛峨・蜃ｦ逅・・ [malware/valleyrat](malware/valleyrat/README.md) 縺ｫ縺ゅｊ縺ｾ縺吶・
## C2 live checks

C2生存確認は `common/c2_detector.py` に統合されている。profileにレビュー済み`live_c2_targets`があり、実行時に`-AllowLiveC2Check`を指定した場合だけ自動解析の末尾で実行する。TLS対象のJARMは追加で`-CollectJarm`を指定する。詳細は [C2-LIVENESS.md](common/C2-LIVENESS.md) を参照。

## Malware type selection, detector routing, and VirusTotal sandbox evidence

`classifiers/classify_sample.py` supports two modes:

- Default mode runs every detector registered in `registry/malware_types.json` and selects the malware type from observed structure or known SHA-256.
- `--malware-type <registered-type>` restricts detection to one registered type. This is useful when starting a new analysis with analyst context, but campaign selection still requires detector observations; an explicit family value alone produces `campaign_type: unknown` when structure does not match.

Example:

```bash
python analysis-framework/classifiers/classify_sample.py \
  --sample /path/to/sample.zip \
  --registry analysis-framework/registry/malware_types.json \
  --malware-type valleyrat \
  --output /tmp/classification.json
```

`Invoke-Analysis.ps1` forwards the same selection through `-MalwareType`. It can also collect VirusTotal sandbox behaviour summaries with `-VirusTotalApiKey` (or `VT_API_KEY`). The fetched `virustotal-sandbox.json` is intended as correlation evidence only: process-attributed sandbox network activity must still be correlated with decoded configuration, loader chains, or other static evidence before promoting an endpoint to confirmed C2.

Standalone VirusTotal sandbox fetch:

```bash
python analysis-framework/common/vt_sandbox.py \
  --sha256 <sample-sha256> \
  --api-key "$VT_API_KEY" \
  --output /tmp/virustotal-sandbox.json
```
