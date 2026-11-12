# Windows 권한 상승 절차

- Windows 셸에서 SYSTEM으로 올라가기 위한 점검 순서. 토큰 특권 → 서비스 → 자동실행 → 예약 작업 → 자격증명 순서로 확인한다.
- 초기 셸 확보 직후, `whoami /priv`로 시작해 어떤 특권·설정이 열려 있는지 파악할 때.
- cmd·PowerShell 셸 필요. 자동화 열거는 winPEAS(windows/privileges/winPEASany.exe.md), 특권 판정은 windows/privileges/overview.md를 따른다.

## 1. 현재 상태 확인

```powershell
whoami
whoami /groups | findstr /i Mandatory      # 무결성 레벨
whoami /priv                               # 토큰 특권 (첫 실행 필수)
systeminfo | findstr /B /C:"OS"            # OS·빌드
```

## 2. 토큰 특권 기반 상승

```powershell
whoami /priv | findstr /i "SeDebug SeImpersonate SeBackup SeRestore SeTakeOwnership SeLoadDriver"
```

```text
SeImpersonatePrivilege   -> Potato 계열, PrintSpoofer (서비스 계정이면 최빈출)
SeDebugPrivilege         -> LSASS 덤프 -> 해시 크래킹 -> 재인증
SeBackupPrivilege        -> SAM·SYSTEM·전체 파일 읽기
SeTakeOwnershipPrivilege -> 파일·레지스트리 소유권 탈취
SeLoadDriverPrivilege    -> 커널 드라이버 로드
```

- Disabled여도 목록에 보이면 시도 대상이다. 도구가 특권을 알아서 켠다. 상세: windows/privileges/overview.md, SeImpersonatePrivilege.md

## 3. 서비스 설정

```powershell
sc query state= all
sc qc <서비스명>
accesschk.exe /accepteula -uwcqv <사용자> <서비스명>
```

- SERVICE_CHANGE_CONFIG·SERVICE_ALL_ACCESS 권한이 있으면 binPath를 페이로드로 바꾼다.
- 실행 파일 경로가 쓰기 가능한지 icacls로 확인한다(언인토크 경로 포함).

```powershell
icacls "C:\Program Files\App\service.exe"
```

## 4. 자동실행·레지스트리

```powershell
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

- Run 키의 실행 파일이 쓰기 가능하면 교체하고 재로그온을 기다린다.
- AlwaysInstallElevated가 둘 다 0x1이면 msi 패키지가 SYSTEM으로 설치된다: msfvenom으로 msi 생성 → msiexec /i payload.msi /qn

## 5. 예약 작업

```powershell
schtasks /query /fo LIST /v
```

- 높은 권한 계정이 실행하는 작업의 실행 파일이 쓰기 가능한지 확인한다. 상세: windows/cmd/schtasks.md

## 6. 자격증명

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
cmdkey /list
dir /s /b C:\Users\*unattend* C:\Users\*sysprep* 2>nul
```

- cmdkey에 저장된 계정은 runas /savecred로 재사용 가능한지 시험한다.
- SAM·SYSTEM 덤프는 SeBackup 또는 관리자 접근 확보 후: active-directory/mimikatz.md, impacket secretsdump

## 7. 자동화 열거

```powershell
.\winPEASany.exe
```

- 준비·전송·실행·해석은 windows/privileges/winPEASany.exe.md 절차를 따른다.

## 트러블슈팅

- whoami /priv에 아무 특별한 특권이 없으면 서비스·자동실행·자격증명 쪽으로 이동한다. 특권은 서비스 계정일 때만 보이는 경우가 많다.
- accesschk가 없으면 Sysinternals 패키지에서 받아 올린다. windows/tools.md 참고.
- AlwaysInstallElevated가 한쪽만 1이면 동작하지 않는다(HKLM·HKCU 둘 다 1이어야 한다).
- winPEAS에서 빨간 항목이 없으면 수동 점검 항목(2·3·4)을 다시 훑고 자격증명 재사용을 시험한다.
