# 토큰 특권 실습 — 개요

- 목표: SeDebug / SeImpersonate / SeTcb 세 특권을 손으로 직접 확인하고 공격 흐름을 재현한다
- 파일 구성
  - `00-overview.md` — 이 파일 (공통 확인법)
  - `01-SeDebugPrivilege.md`
  - `02-SeImpersonatePrivilege.md`
  - `03-SeTcbPrivilege.md`
  - `04-scenarios-tools.md` — 종합 시나리오 + 도구 운용
- 실습 환경: 로컬 Windows VM(관리자) + 서비스 계정 쉘(웹쉘/MSSQL)이 있으면 베스트

# 공통 확인

- 현재 특권 목록 (쉘 따면 첫 실행)
  - `whoami /priv`
- 특정 특권만 있는지 확인
  - `whoami /priv | findstr /i "SeDebug SeImpersonate SeTcb"`
- 현재 사용자/무결성 레벨 확인
  - `whoami`
  - `whoami /groups | findstr /i "mandatory integrity"`

# 읽는 법

- State가 Disabled여도 된다. 공격 도구가 알아서 켠다 → 목록에 보이면 공격 대상
- 목록에 아예 없으면 못 쓴다
- 웹쉘, MSSQL 같은 서비스 계정 쉘이면 SeImpersonate가 있을 확률이 높다
