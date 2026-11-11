- Python HTTP 클라이언트 라이브러리 requests를 apt 패키지(python3-requests)로 설치하는 명령.
- curl 대신 Python 스크립트로 HTTP 요청(로그인 재현, 토큰 발급, 반복 테스트)을 자동화해야 할 때 미리 설치한다.
- Debian/Kali 계열 apt 환경과 sudo(root) 권한 필요.

apt update && apt install -y python3-requests
