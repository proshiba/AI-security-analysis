# IOC list

| Type | Value | Role | Confidence | Source |
|---|---|---|---|---|
| domain | www.grandfoodtony.com | c2_domain_from_config | confirmed_static_config | iocs.json |
| endpoint | www.grandfoodtony.com:443 | c2_endpoint_tcp_http_udp | confirmed_static_config | iocs.json |
| endpoint | www.grandfoodtony.com:80 | c2_endpoint_tcp_http_udp | confirmed_static_config | iocs.json |
| endpoint | www.grandfoodtony.com:8080 | c2_endpoint_tcp_http_udp | confirmed_static_config | iocs.json |
| file_name | klrbtagt.exe | config_ioc | recorded | README:Decryption and configuration |
| file_path | %ALLUSERSPROFILE%\Chrome\AppData\Update\ChromeUpdate.exe | config_ioc | recorded | README:Decryption and configuration |
| file_path | %windir%\system32\svchost.exe | config_ioc | recorded | README:Decryption and configuration |
| file_path | %windir%\system32\taskhost.exe | config_ioc | recorded | README:Decryption and configuration |
| sha256 | 231d21ceefd5c70aa952e8a21523dfe6b5aae9ae6e2b71a0cdbe4e5430b4f5b3 | submitted_sample | confirmed | directory |
| url | http://www.grandfoodtony.com:443 | shadowpad_config_network | confirmed | config.json |
| url | http://www.grandfoodtony.com:80 | shadowpad_config_network | confirmed | config.json |
| url | http://www.grandfoodtony.com:8080 | shadowpad_config_network | confirmed | config.json |
