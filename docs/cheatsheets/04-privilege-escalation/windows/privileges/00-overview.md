# 토큰 특권 실습 — 개요

- 목표: SeDebug / SeImpersonate / SeTcb 손으로 확인하고 공격 흐름 재현
- 파일 구성
  - `00-overview.md` — 공통 확인법
  - `01-SeDebugPrivilege.md` — LSASS 덤프
  - `02-SeImpersonatePrivilege.md` — Potato 계열
  - `03-SeTcbPrivilege.md` — SYSTEM 후 작업
  - `04-scenarios-tools.md` — 시나리오 + 전송

# 공통 확인

- 현재 특권 목록 (쉘 따면 첫 실행)

```powershell
whoami /priv
```

```text
SeDebugPrivilege              Debug programs                            Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeTcbPrivilege                Act as part of the operating system       Enabled
```

- 특정 특권만 확인

```powershell
whoami /priv | findstr /i "SeDebug SeImpersonate SeTcb"
```

- 현재 사용자 / 무결성 레벨 확인

```powershell
whoami
whoami /groups | findstr /i Mandatory
```

```text
nt authority\system
Mandatory Label\System Mandatory Level   S-1-16-16384
```

# 읽는 법

- State가 Disabled여도 목록에만 보이면 시도한다. 공격 도구가 알아서 켠다
- 목록에 아예 없으면 못 쓴다
- 웹쉘, MSSQL 같은 서비스 계정 쉘이면 SeImpersonate가 있을 확률이 높다
