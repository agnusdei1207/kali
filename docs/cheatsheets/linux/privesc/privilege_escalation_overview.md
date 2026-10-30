# privilege escalation overview (Linux)

## 개요

이 문서는 Linux 권한 상승 단계의 진입점이다. 자동 열거 도구가 주로 출력하는 것을 정리한다.

## 권한 유형 (8진수)

| 권한 | 8진수 | 의미 |
|------|------|------|
| Set User ID (SUID) | 4000 | 파일 소유자(root) 권한으로 실행 |
| Set Group ID (SGID) | 2000 | 파일 그룹 권한으로 실행 |
| Sticky Bit | 1000 | 디렉터리 내 삭제 권한 제한 |

## 자동 열거에서 찾는 것

```bash
# SUID/SGID
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# SGID + SUID 동시
find / -perm -6000 -type f 2>/dev/null

# 실행 권한까지 포함 (소유자/그룹/기타 중 하나라도 실행 가능)
find / -perm -4000 -a -perm /111 -type f 2>/dev/null

# 쓰기 가능한 디렉터리
find / -writable -type d 2>/dev/null
```

## sudo / crontab / 서비스

```bash
sudo -l                        # sudo 가능 명령 확인
sudo -u 다른계정 sudo ...      # 특정 사용자 컨테이너로 실행
crontab -l                    # root crontab 확인
cat /etc/crontab
systemctl list-unit-files --state=running
```

## 경로별 관점

- PATH 조작: `/usr/local/bin`에 사용자 추가 스크립트가 있다 → 역시 확인.
- cron/schedule: 특정 주기로 root 실행이 돌지는지.
- 서비스( systemd ): 특정 서비스를 root로 띄우는 역할? → 악용 후 침해 범위 확장.
- kernel/커널: `/dev/mem`, `/dev/kmem` 접근 가능 여부.

## 주의

- 위 명령은 "후보"다. 자동 진단 도구(linpeas)도 같은 목적으로 쓴다 — [linpeas.md](./linpeas/linpeas.md) 참고.
- 모든 후보를 실행하기 전에, 먼저 권한 조합과 접근 경로를 함께 적는다.
