# 192.168.132.65

> nmap -p- -Pn -sC -sV --open -O -oN scan.txt 192.168.132.65

![](image.png)
┌──(root㉿docker-desktop)-[/]
└─# nmap -p- -Pn -sC -sV --open -O -oN scan.txt 192.168.132.65
Starting Nmap 7.99 ( https://nmap.org ) at 2026-10-06 13:52 +0000
Nmap scan report for 192.168.132.65
Host is up (0.12s latency).
Not shown: 47682 filtered tcp ports (no-response), 17843 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT STATE SERVICE VERSION
21/tcp open ftp Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 04-29-20 10:31PM <DIR> ImapRetrieval
| 01-06-25 04:54AM <DIR> Logs
| 04-29-20 10:31PM <DIR> PopRetrieval
|_04-29-20 10:32PM <DIR> Spool
| ftp-syst:
|_ SYST: Windows_NT
80/tcp open http Microsoft IIS httpd 10.0
| http-methods:
|_ Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
135/tcp open msrpc Microsoft Windows RPC
139/tcp open netbios-ssn Microsoft Windows netbios-ssn
445/tcp open microsoft-ds?
9998/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was /interface/root
| uptime-agent-info: HTTP/1.1 400 Bad Request\x0D
| Content-Type: text/html; charset=us-ascii\x0D
| Server: Microsoft-HTTPAPI/2.0\x0D
| Date: Tue, 06 Oct 2026 13:56:35 GMT\x0D
| Connection: close\x0D
| Content-Length: 326\x0D
| \x0D
| <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">\x0D
| <HTML><HEAD><TITLE>Bad Request</TITLE>\x0D
| <META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>\x0D
| <BODY><h2>Bad Request - Invalid Verb</h2>\x0D
| <hr><p>HTTP Error 400. The request verb is invalid.</p>\x0D
|_</BODY></HTML>\x0D
|_http-server-header: Microsoft-IIS/10.0
17001/tcp open remoting MS .NET Remoting services
49666/tcp open msrpc Microsoft Windows RPC
49667/tcp open msrpc Microsoft Windows RPC
49668/tcp open msrpc Microsoft Windows RPC
OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
No OS matches for host
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
| 3.1.1:
|_ Message signing enabled but not required
| smb2-time:
| date: 2026-10-06T13:56:40
|_ start_date: N/A

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 265.58 seconds

> anonymous FTP test

┌──(root㉿docker-desktop)-[/]
└─# nc -v 192.168.132.65 21
192.168.132.65: inverse host lookup failed: Unknown host
(UNKNOWN) [192.168.132.65] 21 (ftp) open
220 Microsoft FTP Service

┌──(root㉿docker-desktop)-[/]
└─# wget -r ftp://Anonymous:pass@192.168.132.65
--2026-10-06 14:09:42-- ftp://Anonymous:_password_@192.168.132.65/
=> ‘192.168.132.65/.listing’
Connecting to 192.168.132.65:21... connected.
Logging in as Anonymous ... Logged in!
==> SYST ... done. ==> PWD ... done.
==> TYPE I ... done. ==> CWD not needed.
==> PASV ... done. ==> LIST ... done.

> http://192.168.132.65:9998/interface/root#/login

- SmarterMail found

![](image_1.png)

┌──(root㉿docker-desktop)-[/]
└─# http http://192.168.132.65:9998/interface/root#/login
HTTP/1.1 200 OK
Cache-Control: private
Content-Encoding: gzip
Content-Length: 2420
Content-Type: text/html; charset=utf-8
Date: Tue, 06 Oct 2026 13:56:24 GMT
Server: Microsoft-IIS/10.0
Vary: Accept-Encoding
X-AspNetMvc-Version: 5.2

```html
<!DOCTYPE html>
<html ng-app="smartermail" ng-cloak>
  <head>
    <!-- SmarterMail Copyright (c) 2003-2026 SmarterTools Inc.  All Rights Reserved. -->
    <meta charset="utf-8" />
    <!-- <meta name="viewport" content="width=device-width, initial-scale=1"> -->
    <meta
      name="viewport"
      content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=0"
    />

    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <link rel="shortcut icon" type="image/x-icon" href="/favicon.ico" />
    <link
      href="https://fonts.googleapis.com/css?family=Roboto"
      rel="stylesheet"
    />

    <!-- Title set in directive -->
    <title page-title></title>

    <!-- Styles -->
    <link
      href="/interface/output/login-v-100.0.6919.30414.8d65fc3f1d47d00.min.css"
      rel="stylesheet"
    />

    <!-- Font Awesome and Bootstrap -->
    <link
      href="/interface/lib/font-awesome/css/font-awesome.css"
      rel="stylesheet"
      async
    />

    <script>
      var htmlCacheBustQs = "cachebust=100.0.6919.30414.8d65fc3f1d47d00";
      var languageCacheBustQs = "cachebust=8d65fc3f1d47d00";
      var angularLangList = [
        "cs",
        "da",
        "de",
        "en",
        "en-GB",
        "es",
        "fa",
        "fr",
        "it",
        "nl",
        "pt",
        "pt-BR",
        "sv",
        "tr",
        "zh-CN",
        "zh-HK",
        "zh-TW",
      ];
      var angularLangMap = {
        cs: "cs",
        da: "da",
        de: "de",
        en: "en",
        "en-GB": "en-GB",
        es: "es",
        fa: "fa",
        fr: "fr",
        it: "it",
        nl: "nl",
        pt: "pt",
        "pt-BR": "pt-BR",
        sv: "sv",
        tr: "tr",
        "zh-CN": "zh-CN",
        "zh-HK": "zh-HK",
        "zh-TW": "zh-TW",
        "cs*": "cs",
        "da*": "da",
        "de*": "de",
        "en*": "en",
        "es*": "es",
        "fa*": "fa",
        "fr*": "fr",
        "it*": "it",
        "nl*": "nl",
        "pt*": "pt",
        "sv*": "sv",
        "tr*": "tr",
        "zh*": "zh-CN",
      };
      var angularLangNames = [
        { v: "cs", n: "čeština" },
        { v: "da", n: "dansk" },
        { v: "de", n: "Deutsch" },
        { v: "en", n: "English" },
        { v: "en-GB", n: "English (United Kingdom)" },
        { v: "es", n: "español" },
        { v: "fa", n: "فارسی" },
        { v: "fr", n: "français" },
        { v: "it", n: "italiano" },
        { v: "nl", n: "Nederlands" },
        { v: "pt", n: "português" },
        { v: "pt-BR", n: "português (Brasil)" },
        { v: "sv", n: "svenska" },
        { v: "tr", n: "Türkçe" },
        { v: "zh-CN", n: "中文(中国)" },
        { v: "zh-HK", n: "中文(香港特別行政區)" },
        { v: "zh-TW", n: "中文(台灣)" },
      ];
      var cssVersion = "100.0.6919.30414.8d65fc3f1d47d00";
      var stProductVersion = "100.0.6919";
      var stProductBuild = "6919 (Dec 11, 2018)";
      var stSiteRoot = "/";
      var stThemeVersion = "100.0.6919.30414.8d65fc3f1d47d00";
      var debugMode = 0;

      function cachebust(url) {
        if (!url) return null;
        var separator = url.indexOf("?") == -1 ? "?" : "&";
        return url + separator + htmlCacheBustQs;
      }
    </script>
  </head>

  <body onload="$('#loadingInd').hide()">
    <div id="loadingInd" style="height:100%;">
      <div class="spinner">
        <div class="spinner-wrapper">
          <div class="rotator">
            <div class="inner-spin"></div>
            <div class="inner-spin"></div>
          </div>
        </div>
      </div>
    </div>

    <script src="/interface/output/angular-v-100.0.6919.30414.8d65fc3f1d47d00.js"></script>
    <script src="/interface/output/vendor-v-100.0.6919.30414.8d65fc3f1d47d00.js"></script>
    <script src="/interface/output/site-v-100.0.6919.30414.8d65fc3f1d47d00.js"></script>

    <div ui-view class="app-view"></div>
    <div
      class="st-select-overlay"
      style="background-color: rgba(255, 255, 255, 0.5); z-index: 2000; pointer-events:initial;"
      ng-click="$event.stopPropagation()"
      ng-if="spinner.isShown()"
      layout="row"
      layout-align="center center"
    >
      <md-progress-circular
        md-mode="indeterminate"
        md-diameter="84"
      ></md-progress-circular>
    </div>
    <div
      class="st-select-overlay"
      style="background-color: rgba(255, 255, 255, 0.5); z-index: 2000; pointer-events:initial;"
      ng-click="$event.stopPropagation()"
      ng-if="determinateSpinner.isShown()"
      layout="row"
      layout-align="center center"
    >
      <md-progress-circular
        md-mode="determinate"
        value="{{determinateSpinnerValue}}"
        md-diameter="84"
      ></md-progress-circular>
    </div>
    <div id="context-menu-area"></div>
  </body>
</html>
```
