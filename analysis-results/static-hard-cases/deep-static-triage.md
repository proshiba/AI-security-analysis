# Deep static triage

This report was produced without sample execution, emulation, network contact, or raw-artifact persistence.

## Summary

| Metric | Count |
|---|---:|
| total | 80 |
| analyzed | 80 |
| partial | 0 |
| not_found | 0 |
| input_errors | 0 |
| layers_analyzed | 142 |
| budget_limited_cases | 0 |
| protector_marker_cases | 16 |
| expected_children_missing_cases | 1 |

## Cases

| SHA-256 | Family | Category | Status | Layers | Markers | Missing expected layers |
|---|---|---|---|---:|---|---|
| 439b73b50c9e5c161b070a4eafa6a56ddb4ea6daf155b8dc06105028a7d04fd2 | quasarrat | size_budget_exceeded | analyzed | 4 | - | - |
| c40348ae2d031c27d318c831189a2a9b6de0c453f756b8d94c0a3bca4b93c627 | quasarrat | size_budget_exceeded | analyzed | 4 | - | - |
| bf93b1578a876f6bbd0368b9d91e78a5b57b499e906b7ceb8e534c1c55626153 | quasarrat | size_budget_exceeded | analyzed | 4 | - | - |
| 7fc964fe47e08d13c158f808d0d68f3f2b9341dfb1ba6fb2a48690fe27e22682 | redlinestealer | size_budget_exceeded | analyzed | 2 | - | - |
| 7b2a28e5ecbdeb4e608026e8c548ef5f50e4aad5da5ae7bfcc5e9ee05e91e80a | redlinestealer | size_budget_exceeded | analyzed | 2 | - | - |
| 9c0a88ea53c4e0324157542385a1d342101feb51cf7b8cf76e9441376f1f522a | hijackloader | size_budget_exceeded | analyzed | 2 | - | - |
| 3f3ac0a31d28e9bbc85df54dd4300c9b15bf255b192fab15d94505ea1e528b02 | redlinestealer | themida_protector | analyzed | 1 | Themida | - |
| a3fa75fe9b9c0ca9ccdc85ae6733024cbc64c545031aad9150f03fed9335850a | darkcomet | upx_packer | analyzed | 1 | UPX | - |
| da590d16a8738a6c5f055fffcdcb49870e088d37e040bf1fc1880cbf9b3faa51 | njrat | managed_loader_or_obfuscated | analyzed | 22 | - | - |
| 64da4c1638c0e1a6435e2026155f9092e7532235e1a38a8b1c8b9fc85c469f9a | njrat | managed_loader_or_obfuscated | analyzed | 5 | - | - |
| c854317fdfc61855002f0cca0cba147c979a56878b8b211c5d512218877d680c | njrat | managed_loader_or_obfuscated | analyzed | 1 | - | - |
| 72e3fb64a103033837ee52ff73f5c00b2a8536b363431cd1308e7ce00f26908a | redlinestealer | managed_loader_or_obfuscated | analyzed | 1 | - | - |
| cbb753220731503e7974588a48305dcf19d8528d7299f695e05211f845a8f720 | redlinestealer | managed_loader_or_obfuscated | analyzed | 3 | SmartAssembly | - |
| 970d178fff5e535e65917b5b007dbaf5948d32668899bded7d954e5823fb50b9 | snakekeylogger | managed_loader_or_obfuscated | analyzed | 3 | - | - |
| e9a3825e87a0b0a53998c1e695ba4942c47d6f4fdb695038ece3900cc645ad6a | snakekeylogger | managed_loader_or_obfuscated | analyzed | 3 | - | - |
| 02355d3fee5e217b25f9210ad0f6bacc3807b6ef1a59aa4d428c01017dcbcf28 | vidar | koivm_managed_virtualization | analyzed | 2 | KoiVM | - |
| 05f9553616bb5fdbf37bd4036c210929e08d7181de898c1bea1bdae7afb0766f | vidar | koivm_managed_virtualization | analyzed | 2 | KoiVM | - |
| 0c857501e3851072db666386136929c06bcf4c8d3160b41b7d82a3ce9afca1be | vidar | koivm_managed_virtualization | analyzed | 2 | KoiVM | - |
| 3418a369486e9bf2b57023dc0b02cb00f12a5214fca8bae20ff93586cc8c678a | vidar | koivm_managed_virtualization | analyzed | 2 | KoiVM | - |
| 363c46dfb252d7c40d9c3bb63bdc40c2eff0ce16c0c1b77f507d73058104c6e1 | vidar | koivm_managed_virtualization | analyzed | 1 | KoiVM | - |
| 4c17f7ee55f9bf6fa9acaeeb9574feab39ba4a3cccd4426dfa85aaf58b90ae73 | vidar | koivm_managed_virtualization | analyzed | 2 | KoiVM | - |
| 4d4f97f1621334e4075e0229265ac6c5da14754eff1378a7d77ea6d3821e8a33 | vidar | koivm_managed_virtualization | analyzed | 2 | KoiVM | - |
| 87b92fcd04f69f9c132c9f350dbb3686888a5e388b1f787f6a658f09582c0da6 | vidar | koivm_managed_virtualization | analyzed | 2 | KoiVM | - |
| 99e733391ac499e78e535a98551c4d27408abfad4e56fe4c46956636655df29c | vidar | koivm_managed_virtualization | analyzed | 2 | KoiVM | - |
| b67bc78347918209973d633287c4e1f514a0917b8678c2cf2066ba80b2004f78 | vidar | koivm_managed_virtualization | analyzed | 2 | KoiVM | - |
| 09034743ead73365c3077a85036d69c4ef0b0c19bba669db7cd53814b9308889 | stealc | themida_winlicense | analyzed | 1 | - | - |
| 125382411e94398dd47ef364807868a3d2a6a4d4821d1513897278e77ef005b1 | stealc | themida_winlicense | analyzed | 1 | - | - |
| 299c378868c76048c26d0e279655c08305f0ce42e5582fe5005aae776d525a1b | stealc | themida_winlicense | analyzed | 1 | - | - |
| 99e3eaac03d77c6b24ebd5a17326ba051788d58f1f1d4aa6871310419a85d8af | stealc | themida_winlicense | analyzed | 1 | - | - |
| 9b8e5b5f2e62640327fdd1616c62a29ec27eaddad731d66ed331b3a1135fd6cb | stealc | themida_winlicense | analyzed | 1 | - | - |
| ab5f78eaccc4a0f86106c547f828c2da8bd554a855deda50074c8a3cd003513a | stealc | themida_winlicense | analyzed | 1 | - | - |
| b42f055a7a568843360e4b8b46d514de26931303b039b700d15a336b5c53dc0b | stealc | themida_winlicense | analyzed | 1 | - | - |
| e08a69c8611950c16a0d273800acc6083cce9078358a8ff41b4639e02a7b18b0 | stealc | themida_winlicense | analyzed | 1 | - | - |
| e1bdbadb3c03238af26c510775bb0aa63f7221dd43eb6f02a16332e091718779 | stealc | themida_winlicense | analyzed | 1 | - | - |
| eb433e78acbf8dc7dfd0817a7699ebef2b44c5de873aa3cb9e950d7df895d49a | stealc | themida_winlicense | analyzed | 1 | - | - |
| f0947eaff9837140af164952d5ff422e3f9e35cea5c85a67709fb97638d03f12 | stealc | themida_winlicense | analyzed | 1 | - | - |
| d1f04b4bea67cbc6f469855826505a16e706b514858fa73c123df263ad34a292 | stealc | enigma_protector | analyzed | 1 | Enigma | - |
| 0a9eab89753e07a01b1c5e0197acefea9cc05e5f7829823f811e7aa1d7b817b7 | stealc | encrypted_payload_buffer | analyzed | 1 | - | - |
| 1b8433398050753d992dc40ea4c07144b43724a99ec4cf2fdac764645d6d1023 | stealc | encrypted_payload_buffer | analyzed | 1 | - | - |
| 2874b873e12bcdfcf0a37708512e21637e38e5f5b9a2bf0c3b34f72d74c05708 | stealc | encrypted_payload_buffer | analyzed | 1 | - | - |
| 2e5dfbff8ab5200fb4d41562186deb2b720d68ce17c7dee49500a155857e99ab | stealc | encrypted_payload_buffer | analyzed | 1 | - | - |
| 4eb215aa80ea20f514aa4815bc82f872bf7130391e21509aef3a29cb34d3a420 | stealc | encrypted_payload_buffer | analyzed | 1 | - | - |
| 4ff0d58788532f4c0bb9dbc9effe6202dd1adaae2ecb8eebc2d48be8cf4b1895 | stealc | encrypted_payload_buffer | analyzed | 1 | - | - |
| 68ab41d802805f74bde3127b20febf98c31a57ab32de9302e53e681599ac7308 | stealc | encrypted_payload_buffer | analyzed | 1 | - | - |
| 6bfc504449a39316188b90599aa225fef46e6be74d2283725f48bcb2860ec1ca | stealc | encrypted_payload_buffer | analyzed | 1 | - | - |
| 736af94a2fd07dca7397c2b2068bfd1e2a71a716c5ddda5e9cb7da808355487a | stealc | encrypted_payload_buffer | analyzed | 1 | - | - |
| b00335a75190fd3b930329adf19c93b483975cb24cc056bea62b0ef359abe3fa | stealc | encrypted_payload_buffer | analyzed | 1 | - | - |
| b731e3399691950d41e03d76c269ec2a60ca68ed7a2eee4d76635b458f5fbedf | stealc | encrypted_payload_buffer | analyzed | 1 | - | - |
| c9dc79d72ab3131295608a78c6473a8bde3791683e88bebeee9989decb8eb4ee | stealc | encrypted_payload_buffer | analyzed | 1 | - | - |
| ca20c0b93bbebbdcd91cad1a8db0356fb4c5d2e17894bd5a34bfcaa4c78a6a9c | stealc | encrypted_payload_buffer | analyzed | 1 | - | - |
| dda07a7f4225baf73499de332ccfbbcd3197e370b77829f13a9991328b976b37 | stealc | encrypted_payload_buffer | analyzed | 1 | - | - |
| e07d3383a78b7b05cd27cf2f569c6e93026e9f40dff4ccb8ec81efafa6b2b23f | stealc | encrypted_payload_buffer | analyzed | 1 | - | - |
| 0523d96352c2028dd22fe5591db75e08c6d8ad76afd0baf2c0b5ce04ae850439 | stealc | native_high_entropy_wrapper | analyzed | 1 | - | - |
| 0b2079978ba2073cfde3c6bc39847431e4e2ab64db27d592df01c4f93d209ca1 | stealc | native_high_entropy_wrapper | analyzed | 1 | - | - |
| 65fcf2bac887d16fe2d281c53efaa770c73f7e32a2862024cc21f9680ee9efe9 | stealc | native_high_entropy_wrapper | analyzed | 1 | - | - |
| d53599b86cbdc98e7d59ddf760bac28aa25f561a4f125f47544c9cfe41aaca3b | stealc | native_high_entropy_wrapper | analyzed | 1 | - | - |
| f4a7d43dc4cdf21cc7a58af7c66386cea1616658f15b996691fbb85a7cb06b9d | stealc | native_high_entropy_wrapper | analyzed | 1 | - | - |
| 6cb09916c5a8464778c43a5372fe483b53e9c53f0867ec252667f109a58020d3 | stealc | delphi_resource_carrier | analyzed | 2 | - | - |
| 84db5b4abf8d9cc8159a751668dc6c5be7ee4143811e38599d5b134120ceca7d | stealc | delphi_resource_carrier | analyzed | 2 | - | - |
| 86bc655cc2d621be255c11459364357fcc424636630586bcea1c1c4b6f220460 | stealc | delphi_resource_carrier | analyzed | 2 | - | - |
| 52b078c339720a09902be86de5e6875f2f31a8c24091453f96858b294f923924 | stealc | nsis_container | analyzed | 1 | - | - |
| 1dbbf81d6f4b2222b37594e8ff30672bf85fd360f347cbd20b1a5d7b841dd276 | amadey | unknown_native_packer | analyzed | 1 | - | - |
| 43e67fbb1bc6ac4549c216476b2aa4e98a89e74ce4d51b8d72380fdd8cc4edb1 | amadey | unknown_native_packer | analyzed | 1 | - | - |
| 572d806c0b56d27fe05562301de6a9ed45cda3f36aef2f6e370867d9f3847013 | amadey | unknown_native_packer | analyzed | 1 | - | - |
| 78305c8b5e8ead6989a0af09fc6ed8f2ff1b246c0487dfa78fb5b155b554cae9 | amadey | unknown_native_packer | analyzed | 1 | - | - |
| 7d05ae98fea42630b199a45f26e18a7196a8f3509ed703fc918416780fd1f661 | amadey | unknown_native_packer | analyzed | 1 | - | - |
| c72cbb4b668f0f56d9df6359e5d391908a9ef5bb21c8f8eb4445be9197c47ef0 | amadey | unknown_native_packer | analyzed | 1 | - | - |
| d04f0d88706837f7af27edf86b3c0e3241bad8ab43939ddda29dc6541b20eed2 | amadey | unknown_native_packer | analyzed | 1 | - | - |
| e92089c1bcd9543515ccada144422b83f9f0b39b3fc0762d79d6619138a224cb | amadey | unknown_native_packer | analyzed | 1 | - | - |
| ea3b2c23df3162a6fa5c9d22d03f50db30542d7570ef769ded4ef106fb0255f4 | amadey | unknown_native_packer | analyzed | 1 | - | - |
| ee170a14d676b69cab768f8a94e482ee9ad6dc1766038d6e26c24fe2cfbd7677 | amadey | unknown_native_packer | analyzed | 1 | - | - |
| fda0fc105ffd6faae12d08c243fe684be8c69696bd654d733f5caf487b59baae | amadey | unknown_native_packer | analyzed | 1 | - | - |
| fc397bf8ddae5d01a16beb2076261b2a708b7cb3e8fea0898e56127a757153de | valleyrat | native_virtualized_protector | analyzed | 2 | - | - |
| ad4a584f5e622c10703bca28c58ee8372899edb48cc1ccf28a2cff87d1afbf2d | valleyrat | native_virtualized_protector | analyzed | 2 | - | - |
| 81f68f61a8f7cf1accca338fd196051020bf60885aad409332091b759ff818d9 | valleyrat | native_virtualized_protector | analyzed | 2 | - | - |
| 5e815731f67cb070fb1b31272c45bd7f4ecd4a408cbbc68a9545bafc3292d72c | remusstealer | native_state_machine_loader | analyzed | 2 | - | - |
| 78b21599a83dbfad39c17202d37dd2b6d552c9679755bc199a9826f3dd0e40db | remcosrat | native_raw_intermediate_loader | analyzed | 1 | - | e9ed0be544b08189ceca2ec8e6ae8f74d62335ed006f0b207fb211df6bbdcb3a |
| 7215cbe8e5dfed7b22c8bbe8c5f7f35a7848e545d1cdeb60a378baf0be32cb0e | venomrat | managed_control_flow_and_resource_obfuscation | analyzed | 4 | SmartAssembly | - |
| ac6938e03f2a076152ee4ce23a39a0bfcd676e4f0b031574d442b6e2df532646 | shadowpad | nspack | analyzed | 1 | nsPack | - |
| 5cecb26a3f33c24b92a0c8f6f5175da0664b21d7c4216a41694e4a4cad233ca8 | latrodectus | encrypted_string_generation | analyzed | 1 | - | - |

## Case details

### 439b73b50c9e5c161b070a4eafa6a56ddb4ea6daf155b8dc06105028a7d04fd2

- Family: quasarrat
- Priority: P0
- Blockers: legacy_root_size_gate_over_32_mib
- Status: analyzed
- Budget limited: False
- Layer 439b73b50c9e5c161b070a4eafa6a56ddb4ea6daf155b8dc06105028a7d04fd2: format=pe; markers=-; native-routing=-; managed-routing=-
- Layer 9264751fb8792fc0429c27e7a601342d5fbe92d91b2db36ca8bfd06558eabfba: format=rar; markers=-; native-routing=-; managed-routing=-
- Layer bf6b8e42dc61586a83e4cefd0bf09992b5ae32a34f2f3f90cb36ec91aad96036: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 463eae02434b126bc01fc4aa5b1efd88fcb53313b05d180a199bfe064273cefd: format=data; markers=-; native-routing=-; managed-routing=-

### c40348ae2d031c27d318c831189a2a9b6de0c453f756b8d94c0a3bca4b93c627

- Family: quasarrat
- Priority: P0
- Blockers: legacy_root_size_gate_over_32_mib
- Status: analyzed
- Budget limited: False
- Layer c40348ae2d031c27d318c831189a2a9b6de0c453f756b8d94c0a3bca4b93c627: format=pe; markers=-; native-routing=-; managed-routing=-
- Layer 579bdbab60e6ee4c1bbfcc782a6d4c308a82a8d50d9cb57e7ea8a064ca77f4f9: format=rar; markers=-; native-routing=-; managed-routing=-
- Layer bf6b8e42dc61586a83e4cefd0bf09992b5ae32a34f2f3f90cb36ec91aad96036: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 463eae02434b126bc01fc4aa5b1efd88fcb53313b05d180a199bfe064273cefd: format=data; markers=-; native-routing=-; managed-routing=-

### bf93b1578a876f6bbd0368b9d91e78a5b57b499e906b7ceb8e534c1c55626153

- Family: quasarrat
- Priority: P0
- Blockers: legacy_root_size_gate_over_32_mib
- Status: analyzed
- Budget limited: False
- Layer bf93b1578a876f6bbd0368b9d91e78a5b57b499e906b7ceb8e534c1c55626153: format=pe; markers=-; native-routing=-; managed-routing=-
- Layer b963dc46713e88124d2b294f4b5af7ea8df49826cbd6a1beb4d08509c23e6b71: format=rar; markers=-; native-routing=-; managed-routing=-
- Layer bf6b8e42dc61586a83e4cefd0bf09992b5ae32a34f2f3f90cb36ec91aad96036: format=data; markers=-; native-routing=-; managed-routing=-
- Layer ea4898c3cef222bdde9e4d6bc500eb22159dfe6ef339f1588b1e2d45a50d299f: format=data; markers=-; native-routing=-; managed-routing=-

### 7fc964fe47e08d13c158f808d0d68f3f2b9341dfb1ba6fb2a48690fe27e22682

- Family: redlinestealer
- Priority: P0
- Blockers: legacy_root_size_gate_over_32_mib
- Status: analyzed
- Budget limited: False
- Layer 7fc964fe47e08d13c158f808d0d68f3f2b9341dfb1ba6fb2a48690fe27e22682: format=pe; markers=-; native-routing=-; managed-routing=-
- Layer 6f7a3520fb5a30d1c747e7d232b219c1c97a2270429da7aa1f572ac2c60b28be: format=pe; markers=-; native-routing=control_flow_flattening:suspected; managed-routing=-

### 7b2a28e5ecbdeb4e608026e8c548ef5f50e4aad5da5ae7bfcc5e9ee05e91e80a

- Family: redlinestealer
- Priority: P0
- Blockers: legacy_root_size_gate_over_32_mib
- Status: analyzed
- Budget limited: False
- Layer 7b2a28e5ecbdeb4e608026e8c548ef5f50e4aad5da5ae7bfcc5e9ee05e91e80a: format=pe; markers=-; native-routing=-; managed-routing=-
- Layer 6f7a3520fb5a30d1c747e7d232b219c1c97a2270429da7aa1f572ac2c60b28be: format=pe; markers=-; native-routing=control_flow_flattening:suspected; managed-routing=-

### 9c0a88ea53c4e0324157542385a1d342101feb51cf7b8cf76e9441376f1f522a

- Family: hijackloader
- Priority: P0
- Blockers: legacy_root_size_gate_over_32_mib
- Status: analyzed
- Budget limited: False
- Layer 9c0a88ea53c4e0324157542385a1d342101feb51cf7b8cf76e9441376f1f522a: format=pe; markers=-; native-routing=-; managed-routing=-
- Layer d11395157a7d11095feeb425d686cf6998530458799785fc00d1ce6f36eef910: format=pe; markers=-; native-routing=-; managed-routing=-

### 3f3ac0a31d28e9bbc85df54dd4300c9b15bf255b192fab15d94505ea1e528b02

- Family: redlinestealer
- Priority: P0
- Blockers: themida, terminal_layer_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 3f3ac0a31d28e9bbc85df54dd4300c9b15bf255b192fab15d94505ea1e528b02: format=pe; markers=Themida; native-routing=control_flow_flattening:confounded; managed-routing=-

### a3fa75fe9b9c0ca9ccdc85ae6733024cbc64c545031aad9150f03fed9335850a

- Family: darkcomet
- Priority: P0
- Blockers: upx_marker, terminal_layer_not_recovered
- Status: analyzed
- Budget limited: False
- Layer a3fa75fe9b9c0ca9ccdc85ae6733024cbc64c545031aad9150f03fed9335850a: format=pe; markers=UPX; native-routing=control_flow_flattening:confounded, indirect_branch_obfuscation:confounded; managed-routing=-

### da590d16a8738a6c5f055fffcdcb49870e088d37e040bf1fc1880cbf9b3faa51

- Family: njrat
- Priority: P1
- Blockers: managed_loader_or_obfuscated, family_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer da590d16a8738a6c5f055fffcdcb49870e088d37e040bf1fc1880cbf9b3faa51: format=pe; markers=-; native-routing=managed_loader_obfuscation:suspected; managed-routing=managed_control_flow_flattening, resource_obfuscation
- Layer c9ca1ef5bb6a3eb33a9f0f69ab5b4eed17ec08ace8cbfb1a8c0073830d8daaa2: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 2c026d993c0664705c4ee60722c1edd16550a36b2d21c376c0b82e0f9d0e7f9d: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 7a31c904e49affe83a0d997df4883a0a9f9f51bb5e4360978a9d5f9dd1fef1bf: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 71937f2862410b7775026215f0e14b55eb861020ed4ee2fab36e1213227789e6: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 3043b8601c89d3f456d6d4689b74e9d2387e7a587dae50b6c3a76ef4bdc50f9e: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 1880d776e3606f67b59c52c1a7cedaab9436e746b9a97237aced2bd3942a2a79: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 1067bdcaa2fdc85ffa3691bd8e6098ac8efbbef6deb261fcaea93a5aeb5b6b19: format=data; markers=-; native-routing=-; managed-routing=-
- Layer ef35cd686b78e7a3f077900265517b0008da3d351aec37dc3c7a85598471427e: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 22f7167979b327cf136bc8385da052deeab70e2da3beafaf56cd254139ede265: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 775a42d07d1a88f85e70d10b9112b416c78270814591a2cbfe40823d5d6d0826: format=data; markers=-; native-routing=-; managed-routing=-
- Layer e5486660bed57ba5a4ef43d9dc863d34476d3c3994c20f8b39af1cce50bb20e4: format=data; markers=-; native-routing=-; managed-routing=-
- Layer c563e2654cf0d97befbd50edb857f3fffac89e84c9d3af0e91c268f00b6f8742: format=data; markers=-; native-routing=-; managed-routing=-
- Layer ca8fbdbb9fe0f9a3d01d07873811ff6b1ad858118420872d2d8476a2e193bab6: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 6eac9e89205c2c0ca0d3c0bbd0c6ed11cf0d64b6cf2b80a95c188361e2d7547f: format=data; markers=-; native-routing=-; managed-routing=-
- Layer de32ddaf09b7974d58d9661b7b5934acd58256d96d3bf39f196b49277ac4cf7d: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 21a3d53d89531043aabbbe297a40d3acd5477941cf731dfc7bc48f836c93dc31: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 59986576bbb8af470cc36553aa17511764ee58d4684261a9bbe3b5973905e80b: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 7465859b57c6ed822393ac8b16c1d4a3e395218d32a6edc08ea9ff3c0ba3762c: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 2d77cb8a292f75697b275c257387092c5e8a5a4b9839f226a6cd39fc7839402c: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 9eb83d4501d79de32e128cc37bbdd39dd4512ac23dfe1e0af5a3044034031411: format=data; markers=-; native-routing=-; managed-routing=-
- Layer fbae393779b4f01d36111d986d6ba7b70c2285d1fef5403416b075132bb0b76f: format=data; markers=-; native-routing=-; managed-routing=-

### 64da4c1638c0e1a6435e2026155f9092e7532235e1a38a8b1c8b9fc85c469f9a

- Family: njrat
- Priority: P1
- Blockers: managed_loader_or_obfuscated, family_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 64da4c1638c0e1a6435e2026155f9092e7532235e1a38a8b1c8b9fc85c469f9a: format=pe; markers=-; native-routing=managed_loader_obfuscation:suspected; managed-routing=resource_obfuscation
- Layer 5c78f44f41d76dde8c328ef60111dc350224498a4d2a6d37c540bbb9aa53d01c: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 7a09d4c71af5d34d449fc0ba91c8993492828bc5d6a1a3300c3f27df63c56e28: format=pe; markers=-; native-routing=-; managed-routing=managed_control_flow_flattening, constant_obfuscation
- Layer bbedbef76be44bdc22b1e7f493eb3a99f0e0ff45f0bb7ec35a8659870366f5f8: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 51e33313ec3503ffd70f75e8384ddc8d83543c7c0046a301e701e3a938401f6c: format=data; markers=-; native-routing=-; managed-routing=-

### c854317fdfc61855002f0cca0cba147c979a56878b8b211c5d512218877d680c

- Family: njrat
- Priority: P1
- Blockers: managed_loader_or_obfuscated, family_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer c854317fdfc61855002f0cca0cba147c979a56878b8b211c5d512218877d680c: format=pe; markers=-; native-routing=managed_loader_obfuscation:suspected; managed-routing=-

### 72e3fb64a103033837ee52ff73f5c00b2a8536b363431cd1308e7ce00f26908a

- Family: redlinestealer
- Priority: P1
- Blockers: managed_loader_or_obfuscated, family_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 72e3fb64a103033837ee52ff73f5c00b2a8536b363431cd1308e7ce00f26908a: format=pe; markers=-; native-routing=managed_loader_obfuscation:suspected; managed-routing=-

### cbb753220731503e7974588a48305dcf19d8528d7299f695e05211f845a8f720

- Family: redlinestealer
- Priority: P1
- Blockers: managed_loader_or_obfuscated, family_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer cbb753220731503e7974588a48305dcf19d8528d7299f695e05211f845a8f720: format=pe; markers=-; native-routing=managed_loader_obfuscation:suspected; managed-routing=-
- Layer ff1a39017e63fc3f412a680712b63f6864508aa5f7231d67e1a84fe4547846f8: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 59dad66b983788b5010a43080a28ce7a26a33b329fe0205c49a599b66d61ee8f: format=pe; markers=SmartAssembly; native-routing=-; managed-routing=smartassembly

### 970d178fff5e535e65917b5b007dbaf5948d32668899bded7d954e5823fb50b9

- Family: snakekeylogger
- Priority: P1
- Blockers: managed_loader_or_obfuscated, family_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 970d178fff5e535e65917b5b007dbaf5948d32668899bded7d954e5823fb50b9: format=pe; markers=-; native-routing=managed_loader_obfuscation:suspected; managed-routing=-
- Layer 788deebeb4e1ccb301d7cb7f4500fea8fcad683c2f989538697edd9c8307b62c: format=data; markers=-; native-routing=-; managed-routing=-
- Layer dd4ddcb93d369da8437b8f8f1386fec6a5b18251c94e0911c38540bb9a9fa280: format=pe; markers=-; native-routing=-; managed-routing=managed_control_flow_flattening, constant_obfuscation

### e9a3825e87a0b0a53998c1e695ba4942c47d6f4fdb695038ece3900cc645ad6a

- Family: snakekeylogger
- Priority: P1
- Blockers: managed_loader_or_obfuscated, family_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer e9a3825e87a0b0a53998c1e695ba4942c47d6f4fdb695038ece3900cc645ad6a: format=pe; markers=-; native-routing=managed_loader_obfuscation:suspected; managed-routing=-
- Layer e1bc701d06f208583444744ff8897f5d2d02ee7b005c086ca1c9e766786e3731: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 09f0d4777eeb322290a8c8323eab7acf6fa1f97cf1f5813d58df177ee0f8d50d: format=pe; markers=-; native-routing=-; managed-routing=managed_control_flow_flattening, constant_obfuscation

### 02355d3fee5e217b25f9210ad0f6bacc3807b6ef1a59aa4d428c01017dcbcf28

- Family: vidar
- Priority: P0
- Blockers: koivm_runtime, virtualized_cil, static_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 02355d3fee5e217b25f9210ad0f6bacc3807b6ef1a59aa4d428c01017dcbcf28: format=pe; markers=KoiVM; native-routing=-; managed-routing=koi_vm, resource_obfuscation
- Layer 4bb086b841213a79473ee7da8d0dca1437a8728f4b82bcbbdc77af02335b1594: format=data; markers=-; native-routing=-; managed-routing=-

### 05f9553616bb5fdbf37bd4036c210929e08d7181de898c1bea1bdae7afb0766f

- Family: vidar
- Priority: P0
- Blockers: koivm_runtime, virtualized_cil, static_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 05f9553616bb5fdbf37bd4036c210929e08d7181de898c1bea1bdae7afb0766f: format=pe; markers=KoiVM; native-routing=-; managed-routing=koi_vm, resource_obfuscation
- Layer 0069f99ba31c52f1dfc1b1f61dd0062469a9eef45b89175060b41cec598e8850: format=data; markers=-; native-routing=-; managed-routing=-

### 0c857501e3851072db666386136929c06bcf4c8d3160b41b7d82a3ce9afca1be

- Family: vidar
- Priority: P0
- Blockers: koivm_runtime, virtualized_cil, static_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 0c857501e3851072db666386136929c06bcf4c8d3160b41b7d82a3ce9afca1be: format=pe; markers=KoiVM; native-routing=-; managed-routing=koi_vm, resource_obfuscation
- Layer 85b52e26e02eb0bb62e9a92e22fc312275c38aed6cb424393d1473dcc97deeee: format=data; markers=-; native-routing=-; managed-routing=-

### 3418a369486e9bf2b57023dc0b02cb00f12a5214fca8bae20ff93586cc8c678a

- Family: vidar
- Priority: P0
- Blockers: koivm_runtime, virtualized_cil, static_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 3418a369486e9bf2b57023dc0b02cb00f12a5214fca8bae20ff93586cc8c678a: format=pe; markers=KoiVM; native-routing=-; managed-routing=koi_vm, resource_obfuscation
- Layer d27bc56058ab4a7fa61d113154f10a627f8175b245b6498b6c3b5b427c2e98b5: format=data; markers=-; native-routing=-; managed-routing=-

### 363c46dfb252d7c40d9c3bb63bdc40c2eff0ce16c0c1b77f507d73058104c6e1

- Family: vidar
- Priority: P0
- Blockers: koivm_runtime, virtualized_cil, static_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 363c46dfb252d7c40d9c3bb63bdc40c2eff0ce16c0c1b77f507d73058104c6e1: format=pe; markers=KoiVM; native-routing=-; managed-routing=koi_vm

### 4c17f7ee55f9bf6fa9acaeeb9574feab39ba4a3cccd4426dfa85aaf58b90ae73

- Family: vidar
- Priority: P0
- Blockers: koivm_runtime, virtualized_cil, static_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 4c17f7ee55f9bf6fa9acaeeb9574feab39ba4a3cccd4426dfa85aaf58b90ae73: format=pe; markers=KoiVM; native-routing=-; managed-routing=koi_vm, resource_obfuscation
- Layer b481a0cde8dd8ea2b12c7ed4c4cc97dff931da9c2280579d2d97d2fd523f95f0: format=data; markers=-; native-routing=-; managed-routing=-

### 4d4f97f1621334e4075e0229265ac6c5da14754eff1378a7d77ea6d3821e8a33

- Family: vidar
- Priority: P0
- Blockers: koivm_runtime, virtualized_cil, static_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 4d4f97f1621334e4075e0229265ac6c5da14754eff1378a7d77ea6d3821e8a33: format=pe; markers=KoiVM; native-routing=-; managed-routing=koi_vm, resource_obfuscation
- Layer cba5f445f663486fe835ee898c4a431fa414b251052cba0998492173f0bf56ef: format=data; markers=-; native-routing=-; managed-routing=-

### 87b92fcd04f69f9c132c9f350dbb3686888a5e388b1f787f6a658f09582c0da6

- Family: vidar
- Priority: P0
- Blockers: koivm_runtime, virtualized_cil, static_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 87b92fcd04f69f9c132c9f350dbb3686888a5e388b1f787f6a658f09582c0da6: format=pe; markers=KoiVM; native-routing=-; managed-routing=koi_vm, resource_obfuscation
- Layer 73bab626284921eee2e6f146d17f830566a7fae6b5334c4340c344bb98429c7c: format=data; markers=-; native-routing=-; managed-routing=-

### 99e733391ac499e78e535a98551c4d27408abfad4e56fe4c46956636655df29c

- Family: vidar
- Priority: P0
- Blockers: koivm_runtime, virtualized_cil, static_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 99e733391ac499e78e535a98551c4d27408abfad4e56fe4c46956636655df29c: format=pe; markers=KoiVM; native-routing=-; managed-routing=koi_vm, resource_obfuscation
- Layer 8f941ddc62f2b249b6ce2658c93c1b72912f4e69a32753e46cd49e1aae970196: format=data; markers=-; native-routing=-; managed-routing=-

### b67bc78347918209973d633287c4e1f514a0917b8678c2cf2066ba80b2004f78

- Family: vidar
- Priority: P0
- Blockers: koivm_runtime, virtualized_cil, static_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer b67bc78347918209973d633287c4e1f514a0917b8678c2cf2066ba80b2004f78: format=pe; markers=KoiVM; native-routing=-; managed-routing=koi_vm, resource_obfuscation
- Layer 33e8f72ada74b579209b3ccb4d5d53e86b92c1f7196bf26e9f9e1b0ed839a903: format=data; markers=-; native-routing=-; managed-routing=-

### 09034743ead73365c3077a85036d69c4ef0b0c19bba669db7cd53814b9308889

- Family: stealc
- Priority: P0
- Blockers: themida_winlicense_2x, terminal_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 09034743ead73365c3077a85036d69c4ef0b0c19bba669db7cd53814b9308889: format=pe; markers=-; native-routing=-; managed-routing=-

### 125382411e94398dd47ef364807868a3d2a6a4d4821d1513897278e77ef005b1

- Family: stealc
- Priority: P0
- Blockers: themida_winlicense_2x, terminal_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 125382411e94398dd47ef364807868a3d2a6a4d4821d1513897278e77ef005b1: format=pe; markers=-; native-routing=-; managed-routing=-

### 299c378868c76048c26d0e279655c08305f0ce42e5582fe5005aae776d525a1b

- Family: stealc
- Priority: P0
- Blockers: themida_winlicense_2x, terminal_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 299c378868c76048c26d0e279655c08305f0ce42e5582fe5005aae776d525a1b: format=pe; markers=-; native-routing=-; managed-routing=-

### 99e3eaac03d77c6b24ebd5a17326ba051788d58f1f1d4aa6871310419a85d8af

- Family: stealc
- Priority: P0
- Blockers: themida_winlicense_2x, terminal_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 99e3eaac03d77c6b24ebd5a17326ba051788d58f1f1d4aa6871310419a85d8af: format=pe; markers=-; native-routing=-; managed-routing=-

### 9b8e5b5f2e62640327fdd1616c62a29ec27eaddad731d66ed331b3a1135fd6cb

- Family: stealc
- Priority: P0
- Blockers: themida_winlicense_2x, terminal_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 9b8e5b5f2e62640327fdd1616c62a29ec27eaddad731d66ed331b3a1135fd6cb: format=pe; markers=-; native-routing=-; managed-routing=-

### ab5f78eaccc4a0f86106c547f828c2da8bd554a855deda50074c8a3cd003513a

- Family: stealc
- Priority: P0
- Blockers: themida_winlicense_2x, terminal_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer ab5f78eaccc4a0f86106c547f828c2da8bd554a855deda50074c8a3cd003513a: format=pe; markers=-; native-routing=-; managed-routing=-

### b42f055a7a568843360e4b8b46d514de26931303b039b700d15a336b5c53dc0b

- Family: stealc
- Priority: P0
- Blockers: themida_winlicense_2x, terminal_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer b42f055a7a568843360e4b8b46d514de26931303b039b700d15a336b5c53dc0b: format=pe; markers=-; native-routing=-; managed-routing=-

### e08a69c8611950c16a0d273800acc6083cce9078358a8ff41b4639e02a7b18b0

- Family: stealc
- Priority: P0
- Blockers: themida_winlicense_2x, terminal_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer e08a69c8611950c16a0d273800acc6083cce9078358a8ff41b4639e02a7b18b0: format=pe; markers=-; native-routing=-; managed-routing=-

### e1bdbadb3c03238af26c510775bb0aa63f7221dd43eb6f02a16332e091718779

- Family: stealc
- Priority: P0
- Blockers: themida_winlicense_2x, terminal_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer e1bdbadb3c03238af26c510775bb0aa63f7221dd43eb6f02a16332e091718779: format=pe; markers=-; native-routing=-; managed-routing=-

### eb433e78acbf8dc7dfd0817a7699ebef2b44c5de873aa3cb9e950d7df895d49a

- Family: stealc
- Priority: P0
- Blockers: themida_winlicense_2x, terminal_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer eb433e78acbf8dc7dfd0817a7699ebef2b44c5de873aa3cb9e950d7df895d49a: format=pe; markers=-; native-routing=-; managed-routing=-

### f0947eaff9837140af164952d5ff422e3f9e35cea5c85a67709fb97638d03f12

- Family: stealc
- Priority: P0
- Blockers: themida_winlicense_2x, terminal_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer f0947eaff9837140af164952d5ff422e3f9e35cea5c85a67709fb97638d03f12: format=pe; markers=-; native-routing=-; managed-routing=-

### d1f04b4bea67cbc6f469855826505a16e706b514858fa73c123df263ad34a292

- Family: stealc
- Priority: P0
- Blockers: enigma_5x, terminal_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer d1f04b4bea67cbc6f469855826505a16e706b514858fa73c123df263ad34a292: format=pe; markers=Enigma; native-routing=anti_disassembly_or_overlapping_code:suspected; managed-routing=-

### 0a9eab89753e07a01b1c5e0197acefea9cc05e5f7829823f811e7aa1d7b817b7

- Family: stealc
- Priority: P1
- Blockers: encrypted_payload_buffer, decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 0a9eab89753e07a01b1c5e0197acefea9cc05e5f7829823f811e7aa1d7b817b7: format=pe; markers=-; native-routing=-; managed-routing=-

### 1b8433398050753d992dc40ea4c07144b43724a99ec4cf2fdac764645d6d1023

- Family: stealc
- Priority: P1
- Blockers: encrypted_payload_buffer, decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 1b8433398050753d992dc40ea4c07144b43724a99ec4cf2fdac764645d6d1023: format=pe; markers=-; native-routing=-; managed-routing=-

### 2874b873e12bcdfcf0a37708512e21637e38e5f5b9a2bf0c3b34f72d74c05708

- Family: stealc
- Priority: P1
- Blockers: encrypted_payload_buffer, decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 2874b873e12bcdfcf0a37708512e21637e38e5f5b9a2bf0c3b34f72d74c05708: format=pe; markers=-; native-routing=-; managed-routing=-

### 2e5dfbff8ab5200fb4d41562186deb2b720d68ce17c7dee49500a155857e99ab

- Family: stealc
- Priority: P1
- Blockers: encrypted_payload_buffer, decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 2e5dfbff8ab5200fb4d41562186deb2b720d68ce17c7dee49500a155857e99ab: format=pe; markers=-; native-routing=-; managed-routing=-

### 4eb215aa80ea20f514aa4815bc82f872bf7130391e21509aef3a29cb34d3a420

- Family: stealc
- Priority: P1
- Blockers: encrypted_payload_buffer, decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 4eb215aa80ea20f514aa4815bc82f872bf7130391e21509aef3a29cb34d3a420: format=pe; markers=-; native-routing=-; managed-routing=-

### 4ff0d58788532f4c0bb9dbc9effe6202dd1adaae2ecb8eebc2d48be8cf4b1895

- Family: stealc
- Priority: P1
- Blockers: encrypted_payload_buffer, decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 4ff0d58788532f4c0bb9dbc9effe6202dd1adaae2ecb8eebc2d48be8cf4b1895: format=pe; markers=-; native-routing=-; managed-routing=-

### 68ab41d802805f74bde3127b20febf98c31a57ab32de9302e53e681599ac7308

- Family: stealc
- Priority: P1
- Blockers: encrypted_payload_buffer, decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 68ab41d802805f74bde3127b20febf98c31a57ab32de9302e53e681599ac7308: format=pe; markers=-; native-routing=-; managed-routing=-

### 6bfc504449a39316188b90599aa225fef46e6be74d2283725f48bcb2860ec1ca

- Family: stealc
- Priority: P1
- Blockers: encrypted_payload_buffer, decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 6bfc504449a39316188b90599aa225fef46e6be74d2283725f48bcb2860ec1ca: format=pe; markers=-; native-routing=-; managed-routing=-

### 736af94a2fd07dca7397c2b2068bfd1e2a71a716c5ddda5e9cb7da808355487a

- Family: stealc
- Priority: P1
- Blockers: encrypted_payload_buffer, decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 736af94a2fd07dca7397c2b2068bfd1e2a71a716c5ddda5e9cb7da808355487a: format=pe; markers=-; native-routing=-; managed-routing=-

### b00335a75190fd3b930329adf19c93b483975cb24cc056bea62b0ef359abe3fa

- Family: stealc
- Priority: P1
- Blockers: encrypted_payload_buffer, decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer b00335a75190fd3b930329adf19c93b483975cb24cc056bea62b0ef359abe3fa: format=pe; markers=-; native-routing=-; managed-routing=-

### b731e3399691950d41e03d76c269ec2a60ca68ed7a2eee4d76635b458f5fbedf

- Family: stealc
- Priority: P1
- Blockers: encrypted_payload_buffer, decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer b731e3399691950d41e03d76c269ec2a60ca68ed7a2eee4d76635b458f5fbedf: format=pe; markers=-; native-routing=-; managed-routing=-

### c9dc79d72ab3131295608a78c6473a8bde3791683e88bebeee9989decb8eb4ee

- Family: stealc
- Priority: P1
- Blockers: encrypted_payload_buffer, decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer c9dc79d72ab3131295608a78c6473a8bde3791683e88bebeee9989decb8eb4ee: format=pe; markers=-; native-routing=-; managed-routing=-

### ca20c0b93bbebbdcd91cad1a8db0356fb4c5d2e17894bd5a34bfcaa4c78a6a9c

- Family: stealc
- Priority: P1
- Blockers: encrypted_payload_buffer, decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer ca20c0b93bbebbdcd91cad1a8db0356fb4c5d2e17894bd5a34bfcaa4c78a6a9c: format=pe; markers=-; native-routing=-; managed-routing=-

### dda07a7f4225baf73499de332ccfbbcd3197e370b77829f13a9991328b976b37

- Family: stealc
- Priority: P1
- Blockers: encrypted_payload_buffer, decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer dda07a7f4225baf73499de332ccfbbcd3197e370b77829f13a9991328b976b37: format=pe; markers=-; native-routing=-; managed-routing=-

### e07d3383a78b7b05cd27cf2f569c6e93026e9f40dff4ccb8ec81efafa6b2b23f

- Family: stealc
- Priority: P1
- Blockers: encrypted_payload_buffer, decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer e07d3383a78b7b05cd27cf2f569c6e93026e9f40dff4ccb8ec81efafa6b2b23f: format=pe; markers=-; native-routing=-; managed-routing=-

### 0523d96352c2028dd22fe5591db75e08c6d8ad76afd0baf2c0b5ce04ae850439

- Family: stealc
- Priority: P1
- Blockers: high_entropy_native_wrapper, decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 0523d96352c2028dd22fe5591db75e08c6d8ad76afd0baf2c0b5ce04ae850439: format=pe; markers=-; native-routing=-; managed-routing=-

### 0b2079978ba2073cfde3c6bc39847431e4e2ab64db27d592df01c4f93d209ca1

- Family: stealc
- Priority: P1
- Blockers: high_entropy_native_wrapper, decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 0b2079978ba2073cfde3c6bc39847431e4e2ab64db27d592df01c4f93d209ca1: format=pe; markers=-; native-routing=-; managed-routing=-

### 65fcf2bac887d16fe2d281c53efaa770c73f7e32a2862024cc21f9680ee9efe9

- Family: stealc
- Priority: P1
- Blockers: high_entropy_native_wrapper, decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 65fcf2bac887d16fe2d281c53efaa770c73f7e32a2862024cc21f9680ee9efe9: format=pe; markers=-; native-routing=-; managed-routing=-

### d53599b86cbdc98e7d59ddf760bac28aa25f561a4f125f47544c9cfe41aaca3b

- Family: stealc
- Priority: P1
- Blockers: high_entropy_native_wrapper, decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer d53599b86cbdc98e7d59ddf760bac28aa25f561a4f125f47544c9cfe41aaca3b: format=pe; markers=-; native-routing=-; managed-routing=-

### f4a7d43dc4cdf21cc7a58af7c66386cea1616658f15b996691fbb85a7cb06b9d

- Family: stealc
- Priority: P1
- Blockers: high_entropy_native_wrapper, decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer f4a7d43dc4cdf21cc7a58af7c66386cea1616658f15b996691fbb85a7cb06b9d: format=pe; markers=-; native-routing=-; managed-routing=-

### 6cb09916c5a8464778c43a5372fe483b53e9c53f0867ec252667f109a58020d3

- Family: stealc
- Priority: P1
- Blockers: delphi_resource_carrier, payload_decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 6cb09916c5a8464778c43a5372fe483b53e9c53f0867ec252667f109a58020d3: format=pe; markers=-; native-routing=-; managed-routing=-
- Layer d261d1cbdd8b19c28519ec446e65c0457c96e6e2f5599dc6f023cb9aba54be99: format=data; markers=-; native-routing=-; managed-routing=-

### 84db5b4abf8d9cc8159a751668dc6c5be7ee4143811e38599d5b134120ceca7d

- Family: stealc
- Priority: P1
- Blockers: delphi_resource_carrier, payload_decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 84db5b4abf8d9cc8159a751668dc6c5be7ee4143811e38599d5b134120ceca7d: format=pe; markers=-; native-routing=-; managed-routing=-
- Layer d261d1cbdd8b19c28519ec446e65c0457c96e6e2f5599dc6f023cb9aba54be99: format=data; markers=-; native-routing=-; managed-routing=-

### 86bc655cc2d621be255c11459364357fcc424636630586bcea1c1c4b6f220460

- Family: stealc
- Priority: P1
- Blockers: delphi_resource_carrier, payload_decoder_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 86bc655cc2d621be255c11459364357fcc424636630586bcea1c1c4b6f220460: format=pe; markers=-; native-routing=-; managed-routing=-
- Layer d261d1cbdd8b19c28519ec446e65c0457c96e6e2f5599dc6f023cb9aba54be99: format=data; markers=-; native-routing=-; managed-routing=-

### 52b078c339720a09902be86de5e6875f2f31a8c24091453f96858b294f923924

- Family: stealc
- Priority: P1
- Blockers: nsis_terminal_payload_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 52b078c339720a09902be86de5e6875f2f31a8c24091453f96858b294f923924: format=pe; markers=-; native-routing=indirect_branch_obfuscation:suspected; managed-routing=-

### 1dbbf81d6f4b2222b37594e8ff30672bf85fd360f347cbd20b1a5d7b841dd276

- Family: amadey
- Priority: P2
- Blockers: suspected_packed, protector_not_attributed
- Status: analyzed
- Budget limited: False
- Layer 1dbbf81d6f4b2222b37594e8ff30672bf85fd360f347cbd20b1a5d7b841dd276: format=pe; markers=-; native-routing=-; managed-routing=-

### 43e67fbb1bc6ac4549c216476b2aa4e98a89e74ce4d51b8d72380fdd8cc4edb1

- Family: amadey
- Priority: P2
- Blockers: suspected_packed, protector_not_attributed
- Status: analyzed
- Budget limited: False
- Layer 43e67fbb1bc6ac4549c216476b2aa4e98a89e74ce4d51b8d72380fdd8cc4edb1: format=pe; markers=-; native-routing=-; managed-routing=-

### 572d806c0b56d27fe05562301de6a9ed45cda3f36aef2f6e370867d9f3847013

- Family: amadey
- Priority: P2
- Blockers: suspected_packed, protector_not_attributed
- Status: analyzed
- Budget limited: False
- Layer 572d806c0b56d27fe05562301de6a9ed45cda3f36aef2f6e370867d9f3847013: format=pe; markers=-; native-routing=-; managed-routing=-

### 78305c8b5e8ead6989a0af09fc6ed8f2ff1b246c0487dfa78fb5b155b554cae9

- Family: amadey
- Priority: P2
- Blockers: suspected_packed, protector_not_attributed
- Status: analyzed
- Budget limited: False
- Layer 78305c8b5e8ead6989a0af09fc6ed8f2ff1b246c0487dfa78fb5b155b554cae9: format=pe; markers=-; native-routing=-; managed-routing=-

### 7d05ae98fea42630b199a45f26e18a7196a8f3509ed703fc918416780fd1f661

- Family: amadey
- Priority: P2
- Blockers: suspected_packed, protector_not_attributed
- Status: analyzed
- Budget limited: False
- Layer 7d05ae98fea42630b199a45f26e18a7196a8f3509ed703fc918416780fd1f661: format=pe; markers=-; native-routing=-; managed-routing=-

### c72cbb4b668f0f56d9df6359e5d391908a9ef5bb21c8f8eb4445be9197c47ef0

- Family: amadey
- Priority: P2
- Blockers: suspected_packed, protector_not_attributed
- Status: analyzed
- Budget limited: False
- Layer c72cbb4b668f0f56d9df6359e5d391908a9ef5bb21c8f8eb4445be9197c47ef0: format=pe; markers=-; native-routing=-; managed-routing=-

### d04f0d88706837f7af27edf86b3c0e3241bad8ab43939ddda29dc6541b20eed2

- Family: amadey
- Priority: P2
- Blockers: suspected_packed, protector_not_attributed
- Status: analyzed
- Budget limited: False
- Layer d04f0d88706837f7af27edf86b3c0e3241bad8ab43939ddda29dc6541b20eed2: format=pe; markers=-; native-routing=-; managed-routing=-

### e92089c1bcd9543515ccada144422b83f9f0b39b3fc0762d79d6619138a224cb

- Family: amadey
- Priority: P2
- Blockers: suspected_packed, protector_not_attributed
- Status: analyzed
- Budget limited: False
- Layer e92089c1bcd9543515ccada144422b83f9f0b39b3fc0762d79d6619138a224cb: format=pe; markers=-; native-routing=-; managed-routing=-

### ea3b2c23df3162a6fa5c9d22d03f50db30542d7570ef769ded4ef106fb0255f4

- Family: amadey
- Priority: P2
- Blockers: suspected_packed, protector_not_attributed
- Status: analyzed
- Budget limited: False
- Layer ea3b2c23df3162a6fa5c9d22d03f50db30542d7570ef769ded4ef106fb0255f4: format=pe; markers=-; native-routing=-; managed-routing=-

### ee170a14d676b69cab768f8a94e482ee9ad6dc1766038d6e26c24fe2cfbd7677

- Family: amadey
- Priority: P2
- Blockers: suspected_packed, protector_not_attributed
- Status: analyzed
- Budget limited: False
- Layer ee170a14d676b69cab768f8a94e482ee9ad6dc1766038d6e26c24fe2cfbd7677: format=pe; markers=-; native-routing=-; managed-routing=-

### fda0fc105ffd6faae12d08c243fe684be8c69696bd654d733f5caf487b59baae

- Family: amadey
- Priority: P2
- Blockers: suspected_packed, protector_not_attributed
- Status: analyzed
- Budget limited: False
- Layer fda0fc105ffd6faae12d08c243fe684be8c69696bd654d733f5caf487b59baae: format=pe; markers=-; native-routing=-; managed-routing=-

### fc397bf8ddae5d01a16beb2076261b2a708b7cb3e8fea0898e56127a757153de

- Family: valleyrat
- Priority: P0
- Blockers: native_control_flow_obfuscation, overlapping_instructions, opaque_predicates, rdtsc, stack_state_manipulation
- Status: analyzed
- Budget limited: False
- Layer fc397bf8ddae5d01a16beb2076261b2a708b7cb3e8fea0898e56127a757153de: format=ole; markers=-; native-routing=-; managed-routing=-
- Layer db720e674a25318cd09e35d8fae5b43faaa3acf9dfe04f5b6ea23d8c0c414779: format=pe; markers=-; native-routing=virtual_machine_or_protector_dispatch:suspected; managed-routing=-

### ad4a584f5e622c10703bca28c58ee8372899edb48cc1ccf28a2cff87d1afbf2d

- Family: valleyrat
- Priority: P0
- Blockers: native_control_flow_obfuscation, overlapping_instructions, opaque_predicates, rdtsc, stack_state_manipulation
- Status: analyzed
- Budget limited: False
- Layer ad4a584f5e622c10703bca28c58ee8372899edb48cc1ccf28a2cff87d1afbf2d: format=ole; markers=-; native-routing=-; managed-routing=-
- Layer 136bdce277b8c810656eccc0b0e4b47f0fde81e1d5aba86a475a08d96b7a22a9: format=pe; markers=-; native-routing=anti_disassembly_or_overlapping_code:suspected, virtual_machine_or_protector_dispatch:suspected; managed-routing=-

### 81f68f61a8f7cf1accca338fd196051020bf60885aad409332091b759ff818d9

- Family: valleyrat
- Priority: P0
- Blockers: native_control_flow_obfuscation, overlapping_instructions, opaque_predicates, rdtsc, stack_state_manipulation
- Status: analyzed
- Budget limited: False
- Layer 81f68f61a8f7cf1accca338fd196051020bf60885aad409332091b759ff818d9: format=ole; markers=-; native-routing=-; managed-routing=-
- Layer 1982d5168c430ee373e6bcbd99322b844bdb5942f778bc9d4b141e7c27182105: format=pe; markers=-; native-routing=virtual_machine_or_protector_dispatch:suspected; managed-routing=-

### 5e815731f67cb070fb1b31272c45bd7f4ecd4a408cbbc68a9545bafc3292d72c

- Family: remusstealer
- Priority: P1
- Blockers: native_control_flow_obfuscation, custom_state_machine, api_hash_resolver
- Status: analyzed
- Budget limited: False
- Layer 5e815731f67cb070fb1b31272c45bd7f4ecd4a408cbbc68a9545bafc3292d72c: format=pe; markers=-; native-routing=control_flow_flattening:confounded, indirect_branch_obfuscation:confounded; managed-routing=-
- Layer 9a76e1fd65f18059294fbc0e6a69a820c7b9efe840aca94c44f71626e99cff72: format=data; markers=-; native-routing=-; managed-routing=-

### 78b21599a83dbfad39c17202d37dd2b6d552c9679755bc199a9826f3dd0e40db

- Family: remcosrat
- Priority: P1
- Blockers: native_control_flow_obfuscation, raw_code_terminal_layer
- Status: analyzed
- Budget limited: False
- Layer 78b21599a83dbfad39c17202d37dd2b6d552c9679755bc199a9826f3dd0e40db: format=pe; markers=-; native-routing=control_flow_flattening:confounded, indirect_branch_obfuscation:confounded; managed-routing=-

### 7215cbe8e5dfed7b22c8bbe8c5f7f35a7848e545d1cdeb60a378baf0be32cb0e

- Family: venomrat
- Priority: P1
- Blockers: dotnet_reactor_control_flow, smartassembly, opaque_resource
- Status: analyzed
- Budget limited: False
- Layer 7215cbe8e5dfed7b22c8bbe8c5f7f35a7848e545d1cdeb60a378baf0be32cb0e: format=pe; markers=-; native-routing=managed_loader_obfuscation:suspected; managed-routing=method_proxy_obfuscation
- Layer 8dc4b3e1e244be1feaf1deff25cf573e791ae7a611be67eba28cb10710a354f6: format=data; markers=-; native-routing=-; managed-routing=-
- Layer 7a66395f6df32fd158ee78bd5a2018f7986f8cb4fcbb370661a303b4ee25ff05: format=pe; markers=SmartAssembly; native-routing=-; managed-routing=smartassembly, managed_control_flow_flattening
- Layer 00c8990831fb232e92a1c4c5970dafb1d64c4c6fee27d9eea57d02c610659e9a: format=data; markers=-; native-routing=-; managed-routing=-

### ac6938e03f2a076152ee4ce23a39a0bfcd676e4f0b031574d442b6e2df532646

- Family: shadowpad
- Priority: P1
- Blockers: nspack, terminal_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer ac6938e03f2a076152ee4ce23a39a0bfcd676e4f0b031574d442b6e2df532646: format=pe; markers=nsPack; native-routing=control_flow_flattening:confounded, indirect_branch_obfuscation:confounded; managed-routing=-

### 5cecb26a3f33c24b92a0c8f6f5175da0664b21d7c4216a41694e4a4cad233ca8

- Family: latrodectus
- Priority: P1
- Blockers: aes_ctr_string_generation, static_config_not_recovered
- Status: analyzed
- Budget limited: False
- Layer 5cecb26a3f33c24b92a0c8f6f5175da0664b21d7c4216a41694e4a4cad233ca8: format=pe; markers=-; native-routing=-; managed-routing=-
