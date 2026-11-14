# IP spoofing

```bash
# X-Forwarded-For
ffuf -u http://192.168.86.200/FUZZ -H "X-Forwarded-For: 10.10.10.0" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -fc 404,302 -t 50
```
