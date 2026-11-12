# Linux 권한 상승 절차

- Linux 셸에서 root로 올라가기 위한 점검 순서. sudo 설정·SUID 바이너리·cron·PATH·환경·커널 순서로 확인한다.
- 초기 셸 확보 직후, Windows의 whoami /priv에 해당하는 "어떤 권한이 남아 있는지"를 파악할 때.
- 셸과 기본 명령만 있으면 된다. 자동화 열거는 linux/privesc/linpeas/linpeas.md를, 각 기법 상세는 linux/privesc/ 문서를 따른다.

## 1. 현재 상태 확인

```bash
whoami && id
sudo -l                      # sudo로 실행 가능한 명령
uname -a                     # 커널 버전 (공개 익스플로잇 매칭용)
cat /etc/os-release
```

## 2. sudo 설정

```bash
sudo -l
```

- `NOPASSWD:`가 붙은 명령이 있으면 GTFOBins에서 그 바이너리의 shell 항목을 확인한다.
- 예: sudo로 vim·find·less·tar·awk가 허용되면 셸 스폰 가능. 상세: linux/privesc/sudo_privesc.md, sudo_usage.md

## 3. SUID·SGID 바이너리

```bash
find / -perm -4000 -type f 2>/dev/null        # SUID
find / -perm -2000 -type f 2>/dev/null        # SGID
find / -perm -6000 -type f 2>/dev/null        # 둘 다
```

- 비표준 바이너리(운영체제 기본 목록에 없는 것)가 보이면 GTFOBins에 대조한다.
- 상세: linux/privesc/suid.md, sgid.md, gtfobins/

## 4. cron·예약 작업

```bash
cat /etc/crontab
ls -la /etc/cron* /var/spool/cron/crontabs/
systemctl list-timers
```

- root가 실행하는 스크립트의 경로가 쓰기 가능한지 확인한다: `ls -la <스크립트경로>`
- PATH가 상대 경로면 현재 디렉터리에서 우회 바이너리가 실행될 수 있다. 상세: linux/privesc/crontab.md

## 5. 프로세스·서비스·PATH

```bash
ps aux | grep root
cat /etc/passwd | grep -E "sh$|bash$"        # 셸이 있는 사용자
echo $PATH
```

- root로 도는 프로세스가 쓰기 가능한 파일·스크립트를 실행하는지 추적한다. 상세: linux/privesc/process-monitoring/

## 6. 자격증명·키

```bash
ls -la /home/*/.ssh/ /root/.ssh/ 2>/dev/null
cat /etc/shadow 2>/dev/null                   # 읽히면 즉시 크래킹으로
grep -ri "password" /etc /opt /home 2>/dev/null
```

- shadow를 읽었으면 unshadow 후 john·hashcat으로 크래킹한다. 상세: cracking/john/unshadow.md

## 7. 자동화 열거

```bash
# linpeas 전송·실행 (전송은 http.server + wget/curl)
./linpeas.sh
```

- linpeas 해석·실행 절차: linux/privesc/linpeas/linpeas.md

## 트러블슈팅

- sudo -l이 암호를 요구하며 실패하면 현재 계정은 sudo 그룹이 아닐 가능성이 크다. 다른 경로(SUID·cron)로 넘어간다.
- SUID 목록이 표준만 나오면 커널·설정 기반(예: pkexec CVE) 또는 환경 남용으로 전환한다. linux/privesc/information_gathering.md 참고.
- linpeas가 빨간 항목을 주지 않으면 자격증명 재사용·수평 상승(다른 사용자 계정)을 먼저 시험한다.
