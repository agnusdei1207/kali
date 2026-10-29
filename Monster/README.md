# ip: 192.168.165.180

# my: 192.168.45.200/24

# reconnaissance

## port scan

> nmap -Pn -O -oN nmap.txt -sV -sC -p- --open 192.168.165.180

![](image_2.png)
![](image_3.png)
![](image_10.png)

- 135, 139, openssl 1.1.1c, 3389, 5040, 7680, 49664~49669

## subdomain scan

- not found

> ffuf -u http://192.168.165.180 -H "Host:FUZZ.192.168.165.180" -w /usr/share/seclists/Discovery/DNS/namelist.txt

![](image_5.png)

## curl

> curl 192.168.165.180 -s | grep href

- assets path found
- accesssable assets path

![](image.png)

> curl 192.168.165.180/assets

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
> curl -x http://127.0.0.1:80 http://192.168.165.180/assets

![](image_4.png)

> curl -x http://127.0.0.1:80 http://192.168.165.180/assets/

- accessable assets path
-

![](image_6.png)

> curl -x http://127.0.0.1:80 http://192.168.165.180/icons/back.gif

Kevin Hughes, Kevinh@eit.com, September 1995

![](image_8.png)

> curl -X GET -x http://127.0.0.1:80 http://192.168.165.180/assets/icons/folder.gif -O

mailto:postmaster@localhost -> webmaster
<span>Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.3.10</span>

![](image_7.png)

## openssl 1.1.1c -> BOF -> not matching beacuase it is a vulnerability for game of half-life

/usr/share/exploitdb/exploits/linux/remote/22968.c

![](image_9.png)

## 443

## path scan

> ffuf -u http://192.168.165.180/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt -t 50 -fc 403

![](image_11.png)

- blog, assets

## access blog

> curl http://192.168.165.180/blog/

![](image_12.png)

- Monstra 3.0.4

> searchsploit Monstra

- found 3.0.4 -> 6

![](image_13.png)

Monstra CMS 3.0.4 - Remote Code Execution (Authenticated) | php/webapps/49949.py
Monstra CMS 3.0.4 - Remote Code Execution (RCE) | php/webapps/52038.py

> apt install bat
> cat 52038.py | batcat

52038.py needs username, password

- so I look for login form
