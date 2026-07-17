# IOC list

| Type | Value | Role | Confidence | Source |
|---|---|---|---|---|
| domain | websencl.com | c2_domain_from_config | confirmed_static_config | iocs.json |
| endpoint | websencl.com:443 | c2_endpoint_tcp_http | confirmed_static_config | iocs.json |
| endpoint | websencl.com:80 | c2_endpoint_tcp_http | confirmed_static_config | iocs.json |
| endpoint | websencl.com:8080 | c2_endpoint_tcp_http | confirmed_static_config | iocs.json |
| file_name | svchost.exe | config_ioc | recorded | README:Decryption and configuration |
| file_path | %ProgramData%\VMware\RawdskCompatibility\virtual\vmrawdsk.exe | config_ioc | recorded | README:Decryption and configuration |
| file_path | %windir%\system32\svchost.exe | config_ioc | recorded | README:Decryption and configuration |
| file_path | %windir%\system32\taskhost.exe | config_ioc | recorded | README:Decryption and configuration |
| file_path | %windir%\system32\winlogon.exe | config_ioc | recorded | README:Decryption and configuration |
| sha256 | 656582bf82205ac3e10b46cbbcf8abb56dd67092459093f35ce8daa64f379a2c | submitted_sample | confirmed | directory |
| url | http://websencl.com:443 | shadowpad_config_network | confirmed | config.json |
| url | http://websencl.com:80 | shadowpad_config_network | confirmed | config.json |
| url | http://websencl.com:8080 | shadowpad_config_network | confirmed | config.json |
