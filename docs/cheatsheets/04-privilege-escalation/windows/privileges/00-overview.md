# 토큰 특권 실습 — 개요

- 목표: SeDebug / SeImpersonate / SeTcb 세 특권을 손으로 직접 확인하고 공격 흐름을 재현한다
- 파일 구성
  - `00-overview.md` — 이 파일 (공통 확인법)
  - `01-SeDebugPrivilege.md`
  - `02-SeImpersonatePrivilege.md`
  - `03-SeTcbPrivilege.md`
  - `04-scenarios-tools.md` — 종합 시나리오 + 도구 운용
- 실습 환경: 로컬 Windows VM(관리자) + 서비스 계정 쉘(웹쉘/MSSQL)이 있으면 베스트

# 리버스쉘 붙여넣기 규칙 (필수)

- 한 번에 한 블록씩만 붙여넣는다. 두 줄을 한 줄에 합치면 파싱 에러가 난다
- 각 블록은 `; Write-Output DONE_xx`로 끝나서 실행 완료를 눈으로 확인한다
- 먼저 쉘 생존 확인:

```powershell
Write-Output alive; whoami; Write-Output DONE_00
```

```text
alive
nt authority\system
DONE_00
```

# 공통 확인

- 현재 특권 목록 (쉘 따면 첫 실행)

```powershell
whoami /priv; Write-Output DONE_priv
```

```text
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                               State
============================= ========================================= ========
SeDebugPrivilege              Debug programs                            Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeTcbPrivilege                Act as part of the operating system       Enabled
... (중략)
DONE_priv
```

- 특정 특권만 있는지 확인

```powershell
whoami /priv | findstr /i "SeDebug SeImpersonate SeTcb"; Write-Output DONE_find
```

```text
SeDebugPrivilege              Debug programs                            Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeTcbPrivilege                Act as part of the operating system       Enabled
DONE_find
```

- 현재 사용자/무결성 레벨 확인

```powershell
whoami; Write-Output DONE_u; whoami /groups | findstr /i "Mandatory"; Write-Output DONE_g
```

```text
nt authority\system
DONE_u
Mandatory Label\System Mandatory Level                        S-1-16-16384
DONE_g
```

# 읽는 법

- State가 Disabled여도 된다. 공격 도구가 알아서 켠다 → 목록에 보이면 공격 대상
- 목록에 아예 없으면 못 쓴다
- 웹쉘, MSSQL 같은 서비스 계정 쉘이면 SeImpersonate가 있을 확률이 높다
