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
