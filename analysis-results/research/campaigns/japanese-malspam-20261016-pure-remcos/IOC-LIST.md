# IOC 一覧

| 種別 (Type) | 値 (Value) | 役割 (Role) | 確度 (Confidence) | 根拠 (Source) |
|---|---|---|---|---|
| ドメイン | get-file.gilmorebrown.co.nz | case2_delivery_domain | 確認済み | iocs.json |
| ドメイン | get-file.thuthukafs.co.nz | case1_delivery_domain | 確認済み | iocs.json |
| ドメイン | trump.sharevideocenter.com | config_ioc | 記録済み | README:終端config |
| 接続先 | 185.139.214.102:56001 | case2_observed_resolved_endpoint | 中 | iocs.json |
| 接続先 | 23.132.164.3:2404 | case3_c2_endpoint_reported_and_comparison_case_corroborated | 中 | iocs.json |
| 接続先 | 82.47.180.159:56001 | case1_observed_resolved_endpoint | 中 | iocs.json |
| 接続先 | tea.vexexo.com:56001 | case2_c2_endpoint_reported_and_behavior_corroborated | 中 | iocs.json |
| 接続先 | trump.sharevideocenter.com:56001 | case1_configured_c2_and_sandbox_observed | 確認済み | iocs.json |
| 接続先 | trump.sharevideocenter.com:56002 | case1_configured_c2_not_observed_in_run | 確認済み | iocs.json |
| 接続先 | trump.sharevideocenter.com:56003 | case1_configured_c2_not_observed_in_run | 確認済み | iocs.json |
| file_path | %LOCALAPPDATA%\Drivers\macOS\run.py | case1_python_loader_path | 確認済み | iocs.json |
| file_path | %LOCALAPPDATA%\Drivers\run.vbs | case1_persistence_script_path | 確認済み | iocs.json |
| file_path | %LOCALAPPDATA%\Temp\88782.ps1 | case3_reported_powershell_stage_path | 中 | iocs.json |
| file_path | C:\Users\Public\WindowsUpdate\instructions.pdf | case2_encrypted_python_payload_path | 確認済み | iocs.json |
| sha256 | 00cf29534fdc5518b214b28a3b5466bd1e8b7245716352a0afeaf995d775d321 | case1_labz_python_runtime_deployer | 確認済み | iocs.json |
| sha256 | 05391e2014707df5773a41c682e013ef475fff158df70a2647f5d74cc13782fc | case2_decrypted_python_stage | 確認済み | iocs.json |
| sha256 | 172be46175d3f7c9c979a0200ae61b1f0e1977e82cb829923e1e590fd039b809 | case1_donut_embedded_dotnet_loader | 確認済み | iocs.json |
| sha256 | 17648ab02d612f12c4a45ae5fee1f52860aae12c498e00377b77e972de22da64 | case2_encrypted_rar5_stage | 確認済み | iocs.json |
| sha256 | 1b2fa5f26297ad761b09dfbe9a347813b8319397122f7615573a9e354273cb99 | case3_dropped_powershell_external_exact_behavior | 中 | iocs.json |
| sha256 | 2558f63f0bf8090c12e1130678cc6a642386155181005e5a21c1d1fb608b4e14 | case1_dropped_python_loader | 確認済み | iocs.json |
| sha256 | 408a6bd09d20d208bce2ad57c4418ac57e9922e85aeeb4ebd16f42571b74e7a8 | case2_terminal_dotnet_payload | 確認済み | iocs.json |
| sha256 | 59ceb7b47ebb9ed5189afe1afe79a80c854bb2ddec62a23ec2c380465a9598a8 | case2_delivery_zip | 確認済み | iocs.json |
| sha256 | 82aeafab427674c4ab36f5483a6ee136e1bc25c326ce1c04d5abd74722332493 | case1_embedded_purerat_agent_certificate_sha256 | 確認済み | iocs.json |
| sha256 | 8b4691c853ddc52a2e6e3c37e6080053c7a03f32ca0e3ccd6bdd56a89b802015 | case1_encrypted_memory_payload | 確認済み | iocs.json |
| sha256 | 962fcefe103538fc1ccef51e664faf7ce3bb572d4f48eb9020b8200bacee5c13 | case1_delivery_zip | 確認済み | iocs.json |
| sha256 | 996afb1023db6e7a0242dc69e10d4df7ddd314bf2e49c6341f561a99082193a5 | case2_malicious_sideload_dll | 確認済み | iocs.json |
| sha256 | 9f201e04b49a958a120b2ea2e9cda048d94feddd9278b6fe03fb6cac24c05b83 | case1_terminal_managed_payload | 確認済み | iocs.json |
| sha256 | cd8dfd0f587dfece900a7316bf1f98abfd11e3fa92546a304069919148f8ce2e | case1_malicious_sideload_dll | 確認済み | iocs.json |
| sha256 | db2169b7fe6c60e36a7dc58ff85d3c8b828543ad872fb2c386a1811165f51b46 | case2_encrypted_python_payload | 確認済み | iocs.json |
| sha256 | f0a1ff80146ad904ad79b1b36e394e7033e3bba92cdf79967643723be4b9e01a | case3_javascript_external_exact_hash_not_locally_acquired | 中 | iocs.json |
| url | https://get-file.gilmorebrown.co.nz/download.php/Product_Receipt_Damage_Inspection_mp4 | case2_delivery_url_query_removed | 確認済み | iocs.json |
| url | https://get-file.thuthukafs.co.nz/download.php/Complete_Product_Condition_Review_mp4 | case1_delivery_url_query_removed | 確認済み | iocs.json |
