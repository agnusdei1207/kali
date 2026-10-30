# information gathering (정보 수집)

## 개요

권한 상승 전에, 현재 컨테이너의 권한·파일·서비스를 먼저 수집한다.
`linux` 계열 치트시트에서 가장 자주 쓰는 명령들의 묶음이다.

## 계정 / 프로세스 확인

```bash
# 현재 계정의 그룹과 소속
id
whoami
groups

# 프로세스와 실행 중인 서비스
ps aux
ps -p $$          # 현재 쉘의 프로세스
```

## 파일시스템 탐색

```bash
cat /etc/os-release
cat /etc/passwd
sudo cat /etc/shadow        # 권한이 있을 때

ls -la /home
find /home -type f -perm -4000 2>/dev/null
find / -writable -type d 2>/dev/null
```

## 로그 분석

```bash
grep -i password /var/log/auth.log
grep -i 'Accepted' /var/log/auth.log
grep -i sudo /var/log/auth.log
grep -i 'su ' /var/log/auth.log
```

## 기타

```bash
mount | grep -E 'overlay|crow'
ss -tulpn
ip a
```

## 활용

- 위에서 "악용 가능한 한 줄"을 골라내는 것이 이후의 공격 경로의 출발점이다.
- 자동 열거 도구(linpeas)도 같은 목적으로 사용한다 — [linpeas.md](./linpeas/linpeas.md) 참고.
- 결과는 반드시 노트(05-progress-tracker)에 적는다.
