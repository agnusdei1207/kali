10.201.29.44

# Nmap 7.95 scan initiated Wed Aug 6 14:23:39 2025 as: /usr/lib/nmap/nmap -Pn -sV -sC --open -oN nmap.txt 10.201.29.44

Nmap scan report for 10.201.29.44
Host is up (0.38s latency).
Not shown: 967 closed tcp ports (reset), 30 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 71:5a:59:e8:8b:66:d2:37:9c:a7:da:d9:7f:8e:56:e7 (RSA)
| 256 56:e1:b9:04:9b:3d:a5:46:a7:fc:65:b8:cd:9c:23:61 (ECDSA)
|_ 256 51:61:75:36:97:b2:96:12:61:b4:5e:9b:3f:e5:b2:f4 (ED25519)
80/tcp open http Apache httpd 2.4.41 ((Ubuntu))
|\_http-server-header: Apache/2.4.41 (Ubuntu)
|\_http-title: Did not follow redirect to https://futurevera.thm/
443/tcp open ssl/http Apache httpd 2.4.41 ((Ubuntu))
|\_http-server-header: Apache/2.4.41 (Ubuntu)
| ssl-cert: Subject: commonName=futurevera.thm/organizationName=Futurevera/stateOrProvinceName=Oregon/countryName=US
| Not valid before: 2022-03-13T10:05:19
|\_Not valid after: 2023-03-13T10:05:19
|\_ssl-date: TLS randomness does not represent time
|\_http-title: FutureVera
| tls-alpn:
|_ http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Wed Aug 6 14:24:19 2025 -- 1 IP address (1 host up) scanned in 39.32 seconds

┌──(root㉿docker-desktop)-[/]
└─# ffuf -u https://futurevera.thm/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -o ffuf_raft-large-directories.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : https://futurevera.thm/FUZZ
:: Wordlist : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt
:: Output file : ffuf_raft-large-directories.txt
:: File format : json
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 40
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500

---

js [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 347ms]
css [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 340ms]
assets [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 411ms]
server-status [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 408ms]
:: Progress: [62281/62281] :: Job [1/1] :: 94 req/sec :: Duration: [0:10:17] :: Errors: 0 ::

![](https://velog.velcdn.com/images/agnusdei1207/post/c9bf1c1f-1911-4cdc-bce1-b77213d43391/image.png)

# http --verify=no https://futurevera.thm/ -> modified the http command options due to a self-signed certificate

┌──(root㉿docker-desktop)-[/]
└─# http --verify=no https://futurevera.thm/
HTTP/1.1 200 OK
Accept-Ranges: bytes
Connection: Keep-Alive
Content-Encoding: gzip
Content-Length: 1270
Content-Type: text/html
Date: Wed, 06 Aug 2025 14:30:56 GMT
ETag: "11fd-5da15a2613040-gzip"
Keep-Alive: timeout=5, max=100
Last-Modified: Sun, 13 Mar 2022 08:48:57 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding

```html
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
        <meta name="description" content="" />
        <meta name="author" content="" />
        <title>FutureVera</title>
        <link rel="icon" type="image/x-icon" href="assets/favicon.ico" />
        <link href="css/styles.css" rel="stylesheet" />
    </head>
    <body id="page-top">
        <!-- Navigation-->
        <nav class="navbar navbar-expand-lg navbar-dark navbar-custom fixed-top">
            <div class="container px-5">
                <a class="navbar-brand" href="#page-top">FutureVera</a>
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarResponsive" aria-controls="navbarResponsive" aria-expanded="false" aria-label="Toggle navigation"><span class="navbar-toggler-icon"></span></button>
            </div>
        </nav>
        <!-- Header-->
        <header class="masthead text-center text-white">
            <div class="masthead-content">
                <div class="container px-5">
                    <h1 class="masthead-heading mb-0">FutureVera</h1>
                    <h2 class="masthead-subheading mb-0">We Will Change the Future Together</h2>
                    <a class="btn btn-primary btn-xl rounded-pill mt-5" href="#scroll">Learn More</a>
                </div>
            </div>
            <div class="bg-circle-1 bg-circle"></div>
            <div class="bg-circle-2 bg-circle"></div>
            <div class="bg-circle-3 bg-circle"></div>
            <div class="bg-circle-4 bg-circle"></div>
        </header>
        <!-- Content section 1-->
        <section id="scroll">
            <div class="container px-5">
                <div class="row gx-5 align-items-center">
                    <div class="col-lg-6 order-lg-2">
                        <div class="p-5"><img class="img-fluid rounded-circle" src="assets/img/01.jpg" alt="..." /></div>
                    </div>
                    <div class="col-lg-6 order-lg-1">
                        <div class="p-5">
                            <h2 class="display-4">Space is the future</h2>
                            <p>Mankind's survival into the far future will very likely require extensive space colonization.</p>
                        </div>
                    </div>
                </div>
            </div>
        </section>
        <!-- Content section 2-->
        <section>
            <div class="container px-5">
                <div class="row gx-5 align-items-center">
                    <div class="col-lg-6">
                        <div class="p-5"><img class="img-fluid rounded-circle" src="assets/img/02.jpg" alt="..." /></div>
                    </div>
                    <div class="col-lg-6">
                        <div class="p-5">
                            <h2 class="display-4">Search for Earth alike planets is on.</h2>
                            An Earth analog (also referred to as an Earth analogue, Earth twin, or Earth-like planet, though this latter term may refer to any terrestrial planet) is a planet or moon with environmental conditions similar to those found on Earth.</p>
                        </div>
                    </div>
                </div>
            </div>
        </section>
        <!-- Content section 3-->
        <section>
            <div class="container px-5">
                <div class="row gx-5 align-items-center">
                    <div class="col-lg-6 order-lg-2">
                        <div class="p-5"><img class="img-fluid rounded-circle" src="assets/img/03.jpg" alt="..." /></div>
                    </div>
                    <div class="col-lg-6 order-lg-1">
                        <div class="p-5">
                            <h2 class="display-4">Our Goal !</h2>
                            <p>Our major goal is to educate masses about space, the future of space travels and the possibilities. Along with that we are also doing our own space research.</p>
                        </div>
                    </div>
                </div>
            </div>
        </section>
        <!-- Footer-->
        <footer class="py-5 bg-black">
            <div class="container px-5"><p class="m-0 text-center text-white small">Copyright &copy;futurevera.thm</p></div>
        </footer>
        <!-- Bootstrap core JS-->
        <script src="js/bootstrap.bundle.min.js"></script>
        <!-- Core theme JS-->
        <script src="js/scripts.js"></script>
    </body>
</html>
```

![](https://velog.velcdn.com/images/agnusdei1207/post/2280862a-897b-428c-814e-7846f75fa141/image.png)

┌──(root㉿docker-desktop)-[/]
└─# http --verify=no https://futurevera.thm/server-status
HTTP/1.1 403 Forbidden
Connection: Keep-Alive
Content-Length: 280
Content-Type: text/html; charset=iso-8859-1
Date: Wed, 06 Aug 2025 14:41:42 GMT
Keep-Alive: timeout=5, max=100
Server: Apache/2.4.41 (Ubuntu)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at futurevera.thm Port 443</address>
</body></html>

# ip : 10.201.29.44

┌──(root㉿docker-desktop)-[/]
└─# ffuf -u http://10.201.29.44 -H "Host: FUZZ.futurevera.thm" -o subdomain.txt -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -fs 0

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://10.201.29.44
:: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
:: Header : Host: FUZZ.futurevera.thm
:: Output file : subdomain.txt
:: File format : json
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 40
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500
:: Filter : Response size: 0

---

portal [Status: 200, Size: 69, Words: 9, Lines: 2, Duration: 343ms]
Portal [Status: 200, Size: 69, Words: 9, Lines: 2, Duration: 412ms]
payroll [Status: 200, Size: 70, Words: 9, Lines: 2, Duration: 395ms]
PORTAL [Status: 200, Size: 69, Words: 9, Lines: 2, Duration: 339ms]
:: Progress: [62281/62281] :: Job [1/1] :: 102 req/sec :: Duration: [0:10:27] :: Errors: 0 ::

# ip : 10.201.81.37

지시문에 blog 가 있던 힌트 도움 받기

![](https://velog.velcdn.com/images/agnusdei1207/post/d9216172-64e7-4d2d-875c-816f7e1946e8/image.png)

# curl -k -> ignore certification TLS

agnusdei@agnusdeis-MacBook-Air oscp % curl -k https://support.futurevera.thm
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
        <meta name="description" content="" />
        <meta name="author" content="" />
        <title>FutureVera - Support</title>
        <link rel="icon" type="image/x-icon" href="assets/favicon.ico" />
        <link href="css/styles.css" rel="stylesheet" />
    </head>
    <body>
        <!-- Background Video-->
        <video class="bg-video" playsinline="playsinline" autoplay="autoplay" muted="muted" loop="loop"><source src="assets/mp4/bg.mp4" type="video/mp4" /></video>
        <!-- Masthead-->
        <div class="masthead">
            <div class="masthead-content text-white">
                <div class="container-fluid px-4 px-lg-0">
                    <h1 class="fst-italic lh-1 mb-4">We are recreating our Support website.</h1>
                    <p class="mb-5">We're working hard to finish the re-development of our support website.</p>
                </div>
                <div class="col-md-10 col-lg-8 col-xl-7">
                    <div class="small text-center text-muted fst-italic">Copyright &copy;futurevera.thm</div>
                </div>
            </div>
        </div>
	<!-- Theme is taken from https://startbootstrap.com -->
	<!-- Bootstrap core JS-->
        <script src="js/bootstrap.bundle.min.js"></script>
        <!-- Core theme JS-->
        <script src="js/scripts.js"></script>
    </body>
</html>


curl -k -v https://support.futurevera.thm

agnusdei@agnusdeis-MacBook-Air oscp % curl -k -v https://support.futurevera.thm

* Host support.futurevera.thm:443 was resolved.
* IPv6: (none)
* IPv4: 10.201.81.37
*   Trying 10.201.81.37:443...
* Connected to support.futurevera.thm (10.201.81.37) port 443
* ALPN: curl offers h2,http/1.1
* (304) (OUT), TLS handshake, Client hello (1):
* (304) (IN), TLS handshake, Server hello (2):
* (304) (IN), TLS handshake, Unknown (8):
* (304) (IN), TLS handshake, Certificate (11):
* (304) (IN), TLS handshake, CERT verify (15):
* (304) (IN), TLS handshake, Finished (20):
* (304) (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / AEAD-CHACHA20-POLY1305-SHA256 / [blank] / UNDEF
* ALPN: server accepted http/1.1
* Server certificate:
*  subject: C=US; ST=Oregon; L=Portland; O=Futurevera; OU=Thm; CN=support.futurevera.thm
*  start date: Mar 13 14:26:24 2022 GMT
*  expire date: Mar 12 14:26:24 2024 GMT
*  issuer: C=US; ST=Oregon; L=Portland; O=Futurevera; OU=Thm; CN=support.futurevera.thm
*  SSL certificate verify result: unable to get local issuer certificate (20), continuing anyway.
* using HTTP/1.x
> GET / HTTP/1.1
> Host: support.futurevera.thm
> User-Agent: curl/8.7.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Date: Thu, 07 Aug 2025 14:34:46 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Last-Modified: Sun, 13 Mar 2022 11:03:32 GMT
< ETag: "5f2-5da1783ba1732"
< Accept-Ranges: bytes
< Content-Length: 1522
< Vary: Accept-Encoding
< Content-Type: text/html
< 
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
        <meta name="description" content="" />
        <meta name="author" content="" />
        <title>FutureVera - Support</title>
        <link rel="icon" type="image/x-icon" href="assets/favicon.ico" />
        <link href="css/styles.css" rel="stylesheet" />
    </head>
    <body>
        <!-- Background Video-->
        <video class="bg-video" playsinline="playsinline" autoplay="autoplay" muted="muted" loop="loop"><source src="assets/mp4/bg.mp4" type="video/mp4" /></video>
        <!-- Masthead-->
        <div class="masthead">
            <div class="masthead-content text-white">
                <div class="container-fluid px-4 px-lg-0">
                    <h1 class="fst-italic lh-1 mb-4">We are recreating our Support website.</h1>
                    <p class="mb-5">We're working hard to finish the re-development of our support website.</p>
                </div>
                <div class="col-md-10 col-lg-8 col-xl-7">
                    <div class="small text-center text-muted fst-italic">Copyright &copy;futurevera.thm</div>
                </div>
            </div>
        </div>
        <!-- Theme is taken from https://startbootstrap.com -->
        <!-- Bootstrap core JS-->
        <script src="js/bootstrap.bundle.min.js"></script>
        <!-- Core theme JS-->
        <script src="js/scripts.js"></script>
    </body>
</html>
* Connection #0 to host support.futurevera.thm left intact
agnusdei@agnusdeis-MacBook-Air oscp % 


# DNS 정보 상세 보기

echo | openssl s_client -servername support.futurevera.thm -connect 10.201.81.37:443 2>/dev/null | openssl x509 -text -noout


* Connection #0 to host support.futurevera.thm left intact
agnusdei@agnusdeis-MacBook-Air oscp % echo | openssl s_client -servername support.futurevera.thm -connect 10.201.81.37:443 2>/dev/null | openssl x509 -text -noout | grep -A 5 "Subject Alternative Name"
            X509v3 Subject Alternative Name: 
                DNS:secrethelpdesk934752.support.futurevera.thm
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        93:51:84:0b:22:3b:07:6b:8d:82:40:38:24:a8:e8:e6:33:19:
        5b:c3:e6:04:de:50:5f:85:fc:ec:de:40:cb:4c:b5:f4:c5:da:
agnusdei@agnusdeis-MacBook-Air oscp % 
echo | openssl s_client -servername support.futurevera.thm -connect 10.201.81.37:443 2>/dev/null | openssl x509 -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            6a:e5:b7:73:1d:02:cd:10:73:a9:88:e0:e4:73:1a:3f:00:88:6c:92
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, ST=Oregon, L=Portland, O=Futurevera, OU=Thm, CN=support.futurevera.thm
        Validity
            Not Before: Mar 13 14:26:24 2022 GMT
            Not After : Mar 12 14:26:24 2024 GMT
        Subject: C=US, ST=Oregon, L=Portland, O=Futurevera, OU=Thm, CN=support.futurevera.thm
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:9a:9b:64:c8:70:9a:13:d1:5e:0e:c8:93:eb:02:
                    da:f7:25:6f:c7:d7:8c:6b:3f:14:90:1d:ed:c9:8f:
                    1a:b0:48:7d:47:71:08:75:dc:d7:49:47:26:65:fe:
                    11:68:36:92:89:40:8b:ab:fb:61:0f:37:7d:92:48:
                    7a:00:23:41:72:ef:1f:9c:27:13:4c:8d:e4:65:e5:
                    30:c5:b1:4e:5a:7f:e4:df:ec:fc:e2:f3:19:c5:d1:
                    cf:36:38:e0:b4:44:33:84:f2:c5:61:3f:63:85:33:
                    1f:79:ad:2d:bc:dc:ac:55:c2:3a:42:18:70:73:90:
                    7b:2f:21:52:c3:8c:8b:e1:b3:76:f4:5d:f9:ec:71:
                    aa:3e:1f:d3:cf:ae:82:52:36:43:01:65:ce:59:44:
                    9e:8c:62:d1:e6:ef:83:0f:75:57:66:6d:6b:b2:21:
                    e3:64:68:af:ac:95:0e:f7:c4:a6:61:47:19:58:95:
                    48:54:2e:1c:f1:ba:bb:22:e2:a8:09:4b:94:a9:0d:
                    07:5c:e1:f5:45:77:75:45:6b:d4:c9:d1:55:01:59:
                    4b:17:ba:98:9b:03:70:c5:4e:69:28:19:2c:83:41:
                    18:c4:c0:17:0e:a1:67:1f:a8:5e:95:58:0f:81:24:
                    bf:df:fc:e2:ab:3f:54:c7:b8:0b:90:bc:21:f0:6b:
                    b6:2b
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: 
                Key Encipherment, Data Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Subject Alternative Name: 
                DNS:secrethelpdesk934752.support.futurevera.thm
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        93:51:84:0b:22:3b:07:6b:8d:82:40:38:24:a8:e8:e6:33:19:
        5b:c3:e6:04:de:50:5f:85:fc:ec:de:40:cb:4c:b5:f4:c5:da:
        b5:f8:9a:8d:c0:c5:54:d7:43:d2:c5:2a:84:1b:9f:2d:a1:95:
        6e:98:73:f5:cb:bd:a7:de:09:57:50:4e:44:12:98:c4:3a:a0:
        df:59:ee:95:ed:09:f3:af:ca:d1:a7:57:1e:a1:f2:f1:de:d5:
        c6:36:0e:d4:18:29:74:c2:d3:2f:d9:24:21:25:f6:1b:18:56:
        3e:fe:75:95:bf:7f:8f:c5:15:1a:1d:80:f2:28:da:91:f7:39:
        21:a4:a6:2d:7d:ca:3d:54:75:47:62:20:1b:a3:85:59:c0:b3:
        4c:ea:4b:b2:c4:a5:ea:0d:23:eb:95:94:3e:96:bc:18:0c:f5:
        45:a0:8c:a0:8c:89:ef:1a:fd:57:aa:b1:c9:6b:1c:cd:65:f9:
        5a:0c:c7:34:fb:00:5c:d1:23:0e:0f:76:07:b9:39:e5:6c:8d:
        21:a8:48:2b:d9:d4:fb:21:c3:50:78:41:ab:50:be:c7:e6:d8:
        60:1b:06:ee:71:1b:97:21:7c:aa:cf:51:d4:a6:b3:41:1d:c4:
        f5:4c:ea:14:94:5e:0e:62:6f:55:9c:7c:ef:01:7f:01:71:fc:
        58:f0:de:72


# DNS TLS 잘못 설정되어 있음 -> 원래 DNS -> secrethelpdesk934752.support.futurevera.thm

┌──(root㉿docker-desktop)-[/]
└─# curl -k -v "http://secrethelpdesk934752.support.futurevera.thm"
* Host secrethelpdesk934752.support.futurevera.thm:80 was resolved.
* IPv6: (none)
* IPv4: 10.201.81.37
*   Trying 10.201.81.37:80...
* Connected to secrethelpdesk934752.support.futurevera.thm (10.201.81.37) port 80
* using HTTP/1.x
> GET / HTTP/1.1
> Host: secrethelpdesk934752.support.futurevera.thm
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 302 Found
< Date: Thu, 07 Aug 2025 14:43:53 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Location: http://flag{beea0d6edfcee06a59b83fb50ae81b2f}.s3-website-us-west-3.amazonaws.com/
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host secrethelpdesk934752.support.futurevera.thm left intact
