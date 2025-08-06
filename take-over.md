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
