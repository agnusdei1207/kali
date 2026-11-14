### `-H` 옵션 (HTTP 헤더 지정) + subdomain

```bash
ffuf -u http://planning.htb -H "Host:FUZZ.planning.htb" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 178 -t 50 -mc 200,302 -fc 304 > ffuf_result.txt
```
