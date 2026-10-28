# 토큰 특권 실습 — 개요 (Windows)

## 개요

이 문서는 Windows 권한 상승 단계의 시작점이다.
`01-SeDebugPrivilege.md`(SeDebug), `02-SeImpersonatePrivilege.md`(SeImpersonate)을 먼저 읽는다.
나머지 파일이 있으면 순서대로 이어진다.

## 공통 확인

### 현재 특권 목록 (쉘 따르면 첫 실행)

```powershell
whoami /priv
```

### 특정 특권만 확인

```powershell
whoami /priv | findstr /i "SeDebug SeImpersonate SeTcb"
```

### 현재 사용자 / 무결성 레벨 확인

```powershell
whoami
whoami /groups | findstr /i Mandatory
```

## 읽는 법

- State가 Disabled여도 목록에만 보이면 시도한다. 공격 도구가 알아서 켠다.
- 목록에 아예 없으면 못 쓴다.
- 서비스 계정(예: `NETWORK SERVICE`)이라면 SeImpersonate이 있을 확률이 높다.

## 다음 단계

1. SeDebug부터: `procdump`·`mimikatz`로 LSASS를 덤프한다.
2. SeImpersonate부터: Potato/Rogue Potato로 SYSTEM에 도달한다.
3. SeTcb부터: SYSTEM 상태에서 마이그레이드된 자격증명을 사용한다.
- 자세한 절차는 각 파일 본문을 따른다.
- 모든 시도는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.
