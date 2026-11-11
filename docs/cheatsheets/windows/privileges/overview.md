# 토큰 특권 실습 — 개요 (Windows)

> 무엇: Windows 토큰 특권(whoami /priv) 기반 권한 상승 실습 문서들의 시작점 문서로, 현재 특권·무결성 레벨을 확인하는 공통 절차를 담는다
> 언제: Windows 셸을 확보했을 때 whoami /priv를 실행해 SeDebug·SeImpersonate·SeTcb 같은 특권이 보이는지 판정하는 첫 단계
> 조건: Windows 셸 필요. State가 Disabled여도 목록에 보이면 공격 도구가 알아서 켜므로 시도 대상이고, 목록에 없으면 이 경로는 못 쓴다. NETWORK SERVICE 같은 서비스 계정이면 SeImpersonate가 있을 확률이 높다

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
