# RemcosRAT analysis results

Ten MalwareBazaar submissions were triaged without local sample execution. Delivery patterns are kept separate from payload/config clusters because builders and infrastructure may be reused by different operators.

| SHA-256 | Artifact | Pattern | Confirmed C2/config endpoint |
|---|---|---|---|
| [`04052c109be7…`](cases/04052c109be755361fd73902875a6552446525cc09d68a9b81eed56b9386d2e1/README.md) | VBS | `vbs_wmi_powershell_loader` | `102.220.160.21:2404` |
| [`09cc1c776574…`](cases/09cc1c77657400e803310dd7ba58a91854fb275e5b29adf53a6ee2827f848366/README.md) | VBS | `vbs_file_carving_powershell_loader` | `103.67.163.108:2404` |
| [`3682d8c43801…`](cases/3682d8c438017249510aba8865e979b666265be3ffae760d503f17ccb391afac/README.md) | JavaScript | `unicode_marker_powershell_stage` | `thrillermotion.4nmn.com:2022` |
| [`47af1f0d9932…`](cases/47af1f0d9932840767920b3cb2befb3839bbc980e610c6a14327edf1b1682b2d/README.md) | HTA | `hta_png_stage` | `pavementmg.duckdns.org:4450`<br>`pavementmg.duckdns.org:4551`<br>`pavementmg.duckdns.org:4553` |
| [`52bd61ba2153…`](cases/52bd61ba2153572260fc9b8f7eac34b613272c428e715fe6b3505f96e4eacf5d/README.md) | PE32+ | `direct_pe_aot` | `37.27.30.5:2404`<br>`37.27.30.5:2405`<br>`37.27.30.5:2406` |
| [`a1391c592b98…`](cases/a1391c592b986457334a361609a952d930182d892a7dd68ab17e6ea18fa4faf2/README.md) | JavaScript | `unicode_marker_powershell_stage` | `kesmn.com:2404` |
| [`b3d07e47793a…`](cases/b3d07e47793a40bf3d99133b7a58feffe5bf8d27ea42a8e45eba322bc02cf8fb/README.md) | ISO9660 | `iso_double_extension_pe` | `37.27.30.5:2404`<br>`37.27.30.5:2405`<br>`37.27.30.5:2406` |
| [`c4fc9162227b…`](cases/c4fc9162227b35c631fbe623ee30fa7f660ed015915ed66c76942b1583ac3f77/README.md) | PE32 | `direct_native_pe` | not recovered |
| [`d503c1d9574d…`](cases/d503c1d9574deb89855643ab0d1063bc28331cc3a580fe7286a56bfc8b09afc8/README.md) | HTA | `hta_png_stage` | `141.98.10.150:14641`<br>`141.98.10.150:14642`<br>`141.98.10.150:14643`<br>`141.98.10.150:14644` |
| [`d92f3155a058…`](cases/d92f3155a058d19c81eba292df6fa7d5080c684ba6a19d3d04d2bdd24796d53c/README.md) | JavaScript | `js_activex_staged_loader` | `79.141.165.55:2404` |

See `rules/` for family-oriented YARA and Sigma starting points. Rules are hypotheses that require validation against local benign software and telemetry.
