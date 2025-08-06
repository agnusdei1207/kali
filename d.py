import random
import socketserver
import socket
import os
import string

# flag.txt 파일을 읽어서 flag 변수에 저장
flag = open('flag.txt', 'r').read().strip()

# 서버로 메시지를 전송하는 함수
def send_message(server, message):
    enc = message.encode()  # 문자열을 바이트로 인코딩
    server.send(enc)        # 서버 소켓에 전송

# XOR 암호화 후 16진수(hex)로 인코딩하는 함수
def setup(server, key):
    # 실제 동작에서는 위의 flag 변수를 사용하지만, 여기서는 하드코딩된 가짜 flag 사용
    print('flag:', flag)  # 디버깅용 출력
    flag = 'THM{thisisafakeflag}'
    print('key:', key)  # 디버깅용 출력
    xored = ""

    # XOR 연산 수행
    for i in range(0, len(flag)):
        xored += chr(ord(flag[i]) ^ ord(key[i % len(key)]))

    # 결과 문자열을 바이트로 변환한 후 hex로 인코딩
    hex_encoded = xored.encode().hex()
    return hex_encoded

# 클라이언트와의 통신 흐름을 담당하는 함수
def start(server):
    # 랜덤한 5자리 키 생성 (영문 + 숫자 조합)
    res = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
    key = str(res)

    # key로 암호화된 flag1 생성
    hex_encoded = setup(server, key)

    # 클라이언트에게 암호화된 flag 전달
    send_message(server, "This XOR encoded text has flag 1: " + hex_encoded + "\n")

    # 키 입력 요청
    send_message(server, "What is the encryption key? ")

    # 사용자로부터 응답 받기
    key_answer = server.recv(4096).decode().strip()

    try:
        if key_answer == key:
            # 맞춘 경우, flag2 전달
            send_message(server, "Congrats! That is the correct key! Here is flag 2: " + flag + "\n")
            server.close()
        else:
            # 틀린 경우 메시지 출력
            send_message(server, "Close but no cigar\n")
            server.close()
    except:
        # 예외 발생 시
        send_message(server, "Something went wrong. Please try again. :)\n")
        server.close()

# socketserver 라이브러리를 이용한 TCP 서버 핸들러 클래스
class RequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # 클라이언트 연결 시 start 함수 실행
        start(self.request)

# 서버 실행 코드
if __name__ == '__main__':
    socketserver.ThreadingTCPServer.allow_reuse_address = True  # 포트 재사용 설정
    server = socketserver.ThreadingTCPServer(('0.0.0.0', 1337), RequestHandler)  # 1337 포트에서 대기
    server.serve_forever()  # 서버 무한 루프 실행
