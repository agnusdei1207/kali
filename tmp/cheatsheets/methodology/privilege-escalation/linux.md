# 리눅스 권한 상승

## 확인 항목

- sudo 권한
- SUID 비트
- cron 작업

## 명령

```bash
sudo -l
find / -perm -4000 -type f 2>/dev/null
```
