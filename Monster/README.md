# ip: 192.168.165.180

# reconnaissance

## port scan

> nmap -Pn -O -oN nmap.txt -sV -sC -p- --open 192.168.165.180

![](image_2.png)
![](image_3.png)

## subdomain scan

> ffuf -u http://192.168.165.180 -H "Host:FUZZ.192.168.165.180" -w /usr/share/seclists/Discovery/DNS/namelist.txt

## curl

> curl 192.168.165.180 -s | grep href

- assets path found

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
        print(f"{flow.response.headers}")
        del flow.response.headers["Location"]

```

> mitmproxy -s remove_location.py -p 80
> curl -x http://127.0.0.1:80 http://192.168.165.180/assets
