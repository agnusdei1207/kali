# ip: 192.168.165.180

# reconnaissance

## port scan

> nmap -Pn -O -oN nmap.txt -sV -sC -p- --open 192.168.165.180

![](image_2.png)
![](image_3.png)

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
