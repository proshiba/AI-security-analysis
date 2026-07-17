# ValleyRAT analysis results

This index covers all 12 analyzed ValleyRAT or ValleyRAT-linked campaign cases. Each case separates observed behavior from expected family capability and separates distribution infrastructure from final command-and-control infrastructure.

- Detailed behavior and C2 model: [BEHAVIOR-C2.md](BEHAVIOR-C2.md)
- Confidence labels: confirmed, confirmed_config, confirmed_distribution_only, inferred_external, and unverified
- A reachable TCP port, a family tag, or a domain string alone does not prove C2 ownership.
- Samples, recovered executables, plugins, PCAPs, credentials, and Ghidra projects are not stored here.

| SHA-256 prefix | Campaign or chain | C2 or infrastructure role | Confidence |
|---|---|---|---|
| [8bf54a76924a](cases/8bf54a76924ad62e3b5562826f0e491c4c498f166276b071c177b694762199f6/README.md) | dll_sideload_vvas_bundle | 202.95.8.27:6666 and :8888, protocol-bearing endpoints | confirmed |
| [b433ecdf855b](cases/b433ecdf855beaaf91d57522eebe9c9e1c3fc756f711bd79ac1b3ecf6c75016c/README.md) | msi_embedded_cab_custom_actions | www.tq8j.com:443; sandbox-associated 103.45.64.246 | confirmed |
| [942be7e0bd06](cases/942be7e0bd06baa6436f3d441f2fed1344093a5a4cf895f88f8a37cc2b05cfb0/README.md) | installer_overlay_dropper | 150.158.50.175:443 | confirmed |
| [eab4918ea758](cases/eab4918ea7581aececacc1ddf3d86812ea1d203dfae8ab635c66136348e3d534/README.md) | single_pe_direct | 154.81.37.130:4444 and :5555 | confirmed |
| [15015ac752a8](cases/15015ac752a84281d406e0ddf814688dcae0e803394491368b479be4c73fe58f/README.md) | dll_sideload_vvas_bundle | 134.122.128.66:6666 and :8888 | confirmed_config |
| [5bdcf2d4fd8a](cases/5bdcf2d4fd8a65c17237d4808e2b613deb0f54de1b90839f1f8e450d8b2acc19/README.md) | installer_overlay_dropper | 27.124.18.166:63016 and :63026 | confirmed |
| [0e4931df7ea3](cases/0e4931df7ea30255b2820e6bd65b43477897c5c20b0d1ba34fd16b4063d92ebd/README.md) | msi_embedded_pe_staged_download | 8.210.15.149:28300; tlhcoz.net DNS pivot | confirmed |
| [d11e793159f0](cases/d11e793159f0da3c88a9ecebb8e5df88919843a1eeaaf71117377db58224a1ae/README.md) | single_pe_n520_managed | config at 118.107.21.88:9000; interactive C2 at 118.107.21.88:9999 | confirmed |
| [df603ed55cbf](cases/df603ed55cbf6f9d74068b956ab966a7b785eb102e1045f343d96255eb2cdc24/README.md) | inno_installer_silverfox_unresolved | oidng2.duoshit.com to 51.79.18.52:443 | inferred_external |
| [6546aad60371](cases/6546aad603716ebbe02412440e8d8d8e5fd7af80f212c6fe45e50a76f093c6d1/README.md) | upx_nrv2e_silverfox_http_bundle | http://43.198.235.91/getinstall64 is distribution only | confirmed_distribution_only |
| [32146526cbc3](cases/32146526cbc3e98467c0e6fbb684f489015e59bed6a4dcff756f6f82d787c5ab/README.md) | qt_static_obfuscated_silverfox | cqbxbkj.cn to 18.167.91.239; port 8880 remains unverified | mixed_inferred_unverified |
| [f543dcf4f178](cases/f543dcf4f178e464c7b4dc24b463272417d8ada2a7d3a832e177f37e64f10cbd/README.md) | cefclient_libcef_sideload_malspam | ljowqjd.cn; final config unavailable | confirmed_chain_unverified_config |

Shared Sigma and YARA candidates are under rules/sigma and rules/yara. Endpoint-only detection should be combined with process ancestry, image-load relationships, persistence, recovered configuration, or protocol structure.

## Latest refresh

- [2026-07-15: 10 new MalwareBazaar samples](refresh-20260715/README.md)
