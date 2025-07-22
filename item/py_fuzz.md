```py
import socket  # 소켓 통신을 위한 표준 라이브러리

def fuzz_endpoints(ip, port, endpoints):
    # 주어진 IP와 포트에 대해 여러 endpoint 문자열을 전송하여 반응을 확인하는 함수
    for endpoint in endpoints:
        try:
            # 🔹 소켓 생성
            # socket.AF_INET: IPv4 주소 체계 사용 (예: 192.168.0.1)
            # socket.SOCK_STREAM: TCP 프로토콜 사용 (신뢰성 있는 연결 지향 통신)
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # 🔹 서버에 연결 시도
            # connect()는 지정한 IP와 포트 번호로 TCP 연결을 시도
            client_socket.connect((ip, port))

            print(f"Testing: {endpoint}")  # 현재 테스트 중인 endpoint 출력

            # 🔹 엔드포인트 문자열 전송
            # 문자열을 바이트로 인코딩하고 줄바꿈 문자 추가하여 서버에 전송
            client_socket.sendall(endpoint.encode() + b'\n')

            # 🔹 서버 응답 수신
            # 최대 1024바이트 수신; recv는 블로킹 방식으로 응답 대기
            response = client_socket.recv(1024)

            # 🔹 응답 출력
            print(f"Response from {endpoint}: {response.decode()}\n")

            # 🔹 연결 종료
            client_socket.close()
        except Exception as e:
            # 에러 발생 시 해당 endpoint와 함께 에러 메시지 출력
            print(f"Error with {endpoint}: {e}")

# 🔹 테스트할 잠재적인 엔드포인트 리스트 정의
endpoint_list = [
    "some_endpoint",  # 정상적인 엔드포인트로 예상됨
    "shell",          # 셸 접근 시도
    "admin",          # 관리자 권한 요청 시도
    "backup",         # 백업 관련 기능 탐색
    "reset",          # 초기화 기능 테스트
    "login",          # 로그인 엔드포인트
    "help",           # 도움말 엔드포인트
    "root",           # 루트 접근 시도
    "register",       # 회원가입 시도
    "old"             # 이전 버전이나 숨겨진 기능 탐색
]

# 🔹 대상 서버 IP 및 포트 설정 (실제 환경에 맞게 수정 필요)
target_ip = "10.10.247.143"
target_port = 8000

# 🔹 fuzzing 실행
fuzz_endpoints(target_ip, target_port, endpoint_list)

```

---

```py
import socket  # 소켓 통신을 위한 표준 라이브러리
import os

def fuzz_endpoints(ip, port, endpoints):
    for endpoint in endpoints:
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((ip, port))

            print(f"Testing: {endpoint}")
            client_socket.sendall(endpoint.encode() + b'\n')
            response = client_socket.recv(1024)
            print(f"Response from {endpoint}: {response.decode()}\n")

            client_socket.close()
        except Exception as e:
            print(f"Error with {endpoint}: {e}")

# 🔹 네임리스트 파일 경로 (환경에 맞게 수정)
name_file_path = "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt"

# 🔹 파일에서 엔드포인트 리스트 읽기
# 각 줄에서 개행 문자 제거하고 리스트로 저장
with open(name_file_path, "r", encoding="utf-8") as f:
    endpoint_list = [line.strip() for line in f if line.strip()]

# 대상 서버 정보
target_ip = "10.10.154.18"
target_port = 8000

# fuzzing 실행
fuzz_endpoints(target_ip, target_port, endpoint_list)


```
