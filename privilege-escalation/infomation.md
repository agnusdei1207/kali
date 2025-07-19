# 정보 수집

```bash
# adm 그룹에도 속함
id
uid=1001(tim) gid=1001(tim) groups=1001(tim),4(adm)
whoami

# 홈 유저 확인
ls /home

cat /etc/os-release
cat /etc/passwd
cat /etc/shadow

sudo cat /etc/shadow

cat /var/log/auth.log
cat /var/log/syslog

grep -i password /var/log/*   # 패스워드 관련 흔적 빠르게 탐색
grep -i 'Accepted' /var/log/auth.log  # SSH 로그인 성공 내역
grep -i 'sudo' /var/log/auth.log      # sudo 명령 실행 내역
grep -i 'su' /var/log/auth.log        # su 명령 실행 내역
grep -i 'docker' /var/log/auth.log    # 도커 관련 명령 실행 내역
```
