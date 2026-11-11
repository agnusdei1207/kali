# crontab

- 크론잡 확인(cat /etc/crontab, crontab -l)과 등록(crontab -e) 방법을 정리하고, root 소유 크론잡을 권한 상승 경로로 보는 관점까지 담은 문서
- 권한 상승 열거에서 root가 주기적으로 실행하는 스크립트를 찾았을 때, 그 스크립트·디렉터리에 쓰기 권한이 있으면 내용을 교체해 root 셸을 노리는 시점
- 확인은 일반 사용자 권한으로 가능하지만 root의 spool 직접 열람에는 권한이 필요하고, 악용에는 cron이 돌리는 스크립트에 대한 쓰기 권한 등 접근성이 요구된다

## 개요

`crontab`은 크론잡(cron job)을 등록한다. 악용되면 다른 사용자 명령을 주기적으로 실행하므로, 권한 상승 공격의 핵심 경로 중 하나다.

## 확인

```bash
cat /etc/crontab                 # 시스템용 crontab
crontab -l                     # 내 계정의 crontab
crontab -e                     # 편집 (vi)
```

## 실전 공격 시나리오

```bash
# 1) root로 crontab에 공격 명령 등록
crontab /tmp/evil.crontab
/root/malware.sh

# 2) 등록된 job 확인
crontab -l

# 3) job이 실행되는지 관찰 (별도 터미널)
crontab -u root
```

- crontab에 등록된 스크립트는 사용자별로 격리되어 있다. root의 crontab이 가장 강력하다.
- job이 주기적이면 매주 자동 실행된다. 증적을 남길 때 "예약 시각"과 "실행 명령"을 적는다.

## 방어 / 탐지

- `/etc/crontab`, `/var/spool/cron/`의 내용을 열거한다.
- crontab이 비정상적으로 길면(예: 특정 날짜의 반복) 확인한다.
- 공격 경로 후보로 자주 등장하므로, 권한 상승 단계에서 바로 시도한다.

## 참고

- 이 문서는 Linux 전용이다.
- Windows에는 스케줄 작업이 해당된다(04-privilege-escalation/windows 참고).
