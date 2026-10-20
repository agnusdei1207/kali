TARGET_URL = "http://127.0.0.1:8080/phpmyadmin/index.php"
USER_WORDLIST = "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt"
PASS_WORDLIST = "/usr/share/wordlists/seclists/Passwords/Most-Popular-Letter-Passes.txt"
PROXY = "http://192.168.199.189:3128"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
REQUEST_TIMEOUT_SEC = 10

# 커맨드라인 인자 읽기
import sys

# HTTP GET/POST, 세션, 쿠키, 프록시 설정 등
import requests


def load_wordlist(path):
    """워드리드스 파일 로드.
    Args:
        path: 파일 경로
    Returns:
        None
    """
    try:
        # with는 본질적으로 try/finally를 더 깔끔하게 쓰는 축약
        # __enter__: 블록 진입 시 실행 (자원 열기, 값 반환)
        # __exit__: 블록 종료 시 실행 (자원 정리, 예외 처리) -> 이걸 호출해 줌
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            # result = []
            # for line in f:
            #    if line.strip():
            #        result.append(line.strip())
            # return result
            return [line.strip() for line in f if line.strip()]

    # FileNotFoundError -> 파일 없는 에러만 잡음
    # except Exception as e -> 모든 에러 잡음 -> e 에러 객체
    except FileNotFoundError:
        print(f"not found file : {path}")
        return None


def brute_force(url, users, passwords, proxy):
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    return None
