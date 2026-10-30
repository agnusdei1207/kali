# linpeas tip

## 개요

`linpeas` 실행 결과의 빨간색(🔴)은 "거의 확실한 권한 상승 벡터"를 뜻한다.
하지만 빨간색이 아니어도 SUID/SGID가 붙은 사용자 추가 파일은 항상 직접 분석해야 한다.
이 문서는 그 기준을 정리한다.

## 빨간색이 아니어도 확인할 것

| 사유 | 설명 |
|------|------|
| SUID/SGID 부여 | root 권한으로 실행됨 — OSCP 시험의 기본 경로 |
| 사용자 추가 바이너리 | 시스템 기본이 아님 — 취약점이 있을 확률이 높음 |
| 자동 진단 실패 | "Unknown SUID binary"로 표시됐다는 것은 자동 진단이 못 했다는 뜻 |

## 실전 절차

```bash
# 1) SUID/SGID 검색
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# 2) 실행 권한까지 포함 (소유자/그룹/기타 중 하나라도 실행)
find / -perm -4000 -a -perm /111 -type f 2>/dev/null

# 3) 쓰기 가능 디렉터리 탐색 (PATH 변조 후공격)
find / -writable -type d 2>/dev/null

# 4) 대상 바이너리를 실제로 실행해 본다
/tmp/target-suid
```

## 시나리오 예시

- `run_as_root`, `backup.sh` 같은 사용자 추가 스크립트에 SUID가 걸려 있다면,
  - 인자로 임의 명령을 넘겨 실행한다: `run_as_root --cmd "whoami"`
  - 경로 오염, 환경 변수 오염을 시도한다.
- crontab에 root 실행 잡이 등록돼 있다면, job 자체를 수정/추가한다(04-privilege-escalation/linux/crontab.md 참고).
- sudoers 파일의 명령 허용 목록을 확인해, 그 명령으로 파일을 읽는다.

## 정리

- 빨간색이 아니어도 SUID/SGID 사용자 추가 파일은 무조건 분석 대상이다.
- 자동화 도구가 제시한 경로를 그대로 실행하지 말고, 직접 검토한다.
