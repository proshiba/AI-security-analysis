# IOC list

| Type | Value | Role | Confidence | Source |
|---|---|---|---|---|
| domain | fljhcqwe.com | c2_domain_from_config | confirmed_static_config | iocs.json |
| endpoint | fljhcqwe.com:80 | c2_endpoint_tcp_from_config | confirmed_static_config | iocs.json |
| file_name | IVIEWERS.dll | config_ioc | recorded | README:Behavior and configuration |
| file_name | svchost.exe | config_ioc | recorded | README:Behavior and configuration |
| file_name | wsuhost.exe | config_ioc | recorded | README:Behavior and configuration |
| file_path | %ALLUSERSPROFILE%\DRM\Windows_Search_Update\wsuhost.exe | config_ioc | recorded | README:Behavior and configuration |
| file_path | %ProgramFiles%\Windows_Search_Update\wsuhost.exe | config_ioc | recorded | README:Behavior and configuration |
| sha256 | 1e06fd5b9aa0e5260369e52ec2d9f87060941de835234afd198b1d4c0b161678 | iviewers_sideload_component | confirmed | iocs.json |
| sha256 | b3428803a202f39a97a0594cee2950e0975dac82195d98c8df9c66a7fc8b18bc | decoded_shadowpad_payload | confirmed | iocs.json |
| sha256 | d05f80d5ccb1b6d4aea847ad38ef7e8ab619ff33601aa54cc836704e4fb53520 | encrypted_shadowpad_payload | confirmed | iocs.json |
| sha256 | f7ef194f2dcc341ba03f76872cb7c0dfbae8f79118f99cf73dfccfb146c4e966 | submitted_sample | confirmed | directory |
