docker cp universal.ovpn kali:/

apt install openvpn
openvpn --config /universal.ovpn --daemon

apt install procps
ps aux | grep openvpn

apt install iproute2
ip a | grep tun

# 192.168.199.189

nmap -Pn -O -oN nmap.txt -sV -sC -p- 192.168.199.189 --stats-every 1m

┌──(root㉿docker-desktop)-[/]
└─# nmap -Pn -O -oN nmap.txt -sC -sV -p- 192.168.199.189
Starting Nmap 7.991 ( https://nmap.org ) at 2026-10-16 09:45 +0000
Nmap scan report for 192.168.199.189
Host is up (0.091s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT STATE SERVICE VERSION
135/tcp open msrpc Microsoft Windows RPC
139/tcp open netbios-ssn Microsoft Windows netbios-ssn
445/tcp open microsoft-ds?
3128/tcp open http-proxy Squid http proxy 4.14
|_http-server-header: squid/4.14
|_http-title: ERROR: The requested URL could not be retrieved
49666/tcp open msrpc Microsoft Windows RPC
49667/tcp open msrpc Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Microsoft Windows Server 2019 (92%), Microsoft Windows 10 1903 - 22H2 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
| 3.1.1:
|_ Message signing enabled but not required
| smb2-time:
| date: 2026-10-16T09:49:09
|_ start_date: N/A

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 236.62 seconds

- smbclient

┌──(root㉿docker-desktop)-[/]
└─# smbclient -L 192.168.199.189 -N
session setup failed: NT_STATUS_ACCESS_DENIED

┌──(root㉿docker-desktop)-[/]
└─# smbclient //192.168.199.189/anonymous -N
session setup failed: NT_STATUS_ACCESS_DENIED

- smbclient 445 anonymous blocked

┌──(root㉿docker-desktop)-[/]
└─# http http://192.168.199.189:3128
HTTP/1.1 400 Bad Request
Connection: close
Content-Language: en
Content-Length: 3394
Content-Type: text/html;charset=utf-8
Date: Mon, 19 Oct 2026 07:55:03 GMT
Mime-Version: 1.0
Server: squid/4.14
Vary: Accept-Language
Via: 1.1 SQUID (squid/4.14)
X-Cache: MISS from SQUID
X-Squid-Error: ERR_INVALID_URL 0

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>ERROR: The requested URL could not be retrieved</title>
<style type="text/css"><!--
 /*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
Stylesheet for Squid Error pages
Adapted from design by Free CSS Templates
http://www.freecsstemplates.org
Released for free under a Creative Commons Attribution 2.5 License
*/

/* Page basics _/
/_ Page displayed title area */
#titles {
background: url('/squid-internal-static/icons/SN.png') no-repeat left;
}

body
:lang(fa) { direction: rtl; font-size: 100%; font-family: Tahoma, Roya, sans-serif; float: right; }
:lang(he) { direction: rtl; }
--></style>
</head><body id=ERR_INVALID_URL>
<div id="titles">
<h1>ERROR</h1>
<h2>The requested URL could not be retrieved</h2>
</div>
<hr>

<div id="content">
<p>The following error was encountered while trying to retrieve the URL: <a href="/">/</a></p>

<blockquote id="error">
<p><b>Invalid URL</b></p>
</blockquote>

<p>Some aspect of the requested URL is incorrect.</p>

<p>Some possible problems are:</p>
<ul>
<li><p>Missing or incorrect access protocol (should be <q>http://</q> or similar)</p></li>
<li><p>Missing hostname</p></li>
<li><p>Illegal double-escape in the URL-Path</p></li>
<li><p>Illegal character in hostname; underscores are not allowed.</p></li>
</ul>

<p>Your cache administrator is <a href="mailto:webmaster?subject=CacheErrorInfo%20-%20ERR_INVALID_URL&amp;body=CacheHost%3A%20SQUID%0D%0AErrPage%3A%20ERR_INVALID_URL%0D%0AErr%3A%20%5Bnone%5D%0D%0ATimeStamp%3A%20Mon,%2019%20Oct%202026%2007%3A55%3A03%20GMT%0D%0A%0D%0AClientIP%3A%20192.168.45.248%0D%0A%0D%0AHTTP%20Request%3A%0D%0A%0D%0A%0D%0A">webmaster</a>.</p>
<br>
</div>

<hr>
<div id="footer">
<p>Generated Mon, 19 Oct 2026 07:55:03 GMT by SQUID (squid/4.14)</p>
<!-- ERR_INVALID_URL -->
</div>
</body></html>

- squid 4.14 found
