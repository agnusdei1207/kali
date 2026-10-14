                                                                                                                            
# 10.65.154.119

![](https://velog.velcdn.com/images/agnusdei1207/post/c4736a36-eafb-4c80-806e-46ab0308ab01/image.png)

> 통신 암호 분석
> 암호문과 평문을 알면 키를 얻을 수 있는 공식을 이용
> 스트림 대칭키 암호화

```python
# 제공되는 기본 파일
import random # 임의의 키를 생성하는 데 사용
import socketserver # TCP 서버를 쉽게 구축하는 데 사용
import socket, os # 소켓 통신 및 운영체제 관련 기능
import string # 문자열 상수(알파벳, 숫자 등)를 제공

# 서버가 클라이언트에게 최종적으로 제공해야 할 실제 플래그 (flag.txt 파일에서 읽어옴)
flag = open('flag.txt','r').read().strip() 

def send_message(server, message):
    # 클라이언트에게 메시지를 인코딩하여 전송하는 헬퍼 함수
    enc = message.encode()
    server.send(enc)

def setup(server, key):
    # 암호화할 '알려진 평문'을 설정합니다.
    # 이 'THM{...}' 문자열은 모든 사용자가 복호화할 수 있는 '가짜 플래그' 역할을 합니다.
    flag = 'THM{thisisafakeflag}' 
    xored = ""

    # 반복 키 XOR 암호화 수행:
    # 플래그의 각 문자를 키의 해당 문자와 XOR 연산합니다.
    # 'i % len(key)'를 통해 키가 플래그 길이만큼 반복되도록 합니다.
    for i in range(0,len(flag)):
        xored += chr(ord(flag[i]) ^ ord(key[i%len(key)]))

    # XOR된 결과를 16진수 문자열로 인코딩합니다. (클라이언트에게 전송될 암호문)
    hex_encoded = xored.encode().hex()
    return hex_encoded

def start(server):
    # 'a-z, A-Z, 0-9' 중에서 5개의 문자를 무작위로 선택하여 키를 생성합니다.
    res = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
    key = str(res) # 이 5자리 문자열이 실제 암호화 키입니다.
    
    # 생성된 키로 가짜 플래그를 암호화합니다.
    hex_encoded = setup(server, key)
    
    # 클라이언트에게 암호화된 텍스트를 전송합니다.
    send_message(server, "This XOR encoded text has flag 1: " + hex_encoded + "\n")
    
    # 클라이언트에게 키를 입력하라는 메시지를 요청합니다.
    send_message(server,"What is the encryption key? ")
    
    # 클라이언트로부터 응답(키)을 수신합니다.
    key_answer = server.recv(4096).decode().strip()

    try:
        # 클라이언트가 보낸 키와 서버가 생성한 키가 일치하는지 확인합니다.
        if key_answer == key:
            # 키가 맞다면, 최종 플래그(flag.txt에서 읽어온 실제 플래그)를 제공하고 연결을 닫습니다.
            send_message(server, "Congrats! That is the correct key! Here is flag 2: " + flag + "\n")
            server.close()
        else:
            # 키가 틀리다면, 실패 메시지를 보내고 연결을 닫습니다.
            send_message(server, 'Close but no cigar' + "\n")
            server.close()
    except:
        # 키를 수신하는 과정 등에서 오류가 발생하면 에러 메시지를 보냅니다.
        send_message(server, "Something went wrong. Please try again. :)\n")
        server.close()

class RequestHandler(socketserver.BaseRequestHandler):
    # 클라이언트가 서버에 연결할 때마다 실행되는 핸들러 클래스입니다.
    def handle(self):
        # 연결이 들어올 때마다 start 함수를 호출하여 챌린지를 시작합니다.
        start(self.request)

if __name__ == '__main__':
    # 서버가 종료된 후 동일한 주소와 포트를 즉시 재사용할 수 있도록 설정합니다.
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    
    # '0.0.0.0' 주소의 1337 포트에서 서버를 시작하고 요청을 처리할 핸들러를 지정합니다.
    server = socketserver.ThreadingTCPServer(('0.0.0.0', 1337), RequestHandler)
    
    # 서버를 영원히 실행합니다 (무한 루프).
    server.serve_forever()
```


┌──(kali㉿kali)-[~]
└─$ nc 10.65.154.119 1337                                                           
This XOR encoded text has flag 1: 19317c43207c185d56240801457924394d5253330c17430b3121354850053f0d4808253f017e4a2d
What is the encryption key? ^C
                                                                                                                              
┌──(kali㉿kali)-[~]
└─$ chmod 700 ./wise.py 
                                                                                                                              
┌──(kali㉿kali)-[~]
└─$ sudo python3 ./wise.py
[sudo] password for kali: 
usage: wise.py [-h] hex_encoded
wise.py: error: the following arguments are required: hex_encoded
                                                                                                                              
┌──(kali㉿kali)-[~]
└─$ 19317c43207c185d56240801457924394d5253330c17430b3121354850053f0d4808253f017e4a2d
                                                                                                                              
┌──(kali㉿kali)-[~]
└─$ sudo python3 ./wise.py
usage: wise.py [-h] hex_encoded
wise.py: error: the following arguments are required: hex_encoded
                                                                                                                              
┌──(kali㉿kali)-[~]
└─$ sudo python3 ./wise.py 19317c43207c185d56240801457924394d5253330c17430b3121354850053f0d4808253f017e4a2d
Derived start of the key: My18
Derived end of the key: P
Derived key: My18P
Decrypted message: THM{p1alntExtAtt4ckcAnr3alLyhUrty0urxOr}
                                




```python
import socket
import re
import sys
import time

# --- 1. 통신 및 암호화 상수 설정 ---
HOST = '10.65.154.119'
PORT = 1337
# 모든 암호문이 복호화될 것으로 예상되는 플래그 접두사 및 접미사
KNOWN_START_PLAINTEXT = 'THM{'
KNOWN_END_PLAINTEXT = '}'
KEY_LENGTH = 5 

# --- 2. wise.py 핵심 로직 함수 통합 ---

def derive_key_part(hex_encoded, known_plaintext, start_index):
    """암호문과 알려진 평문을 XOR하여 키의 일부를 유도합니다."""
    try:
        # 16진수 문자열을 바이트로 변환
        encrypted_bytes = bytes.fromhex(hex_encoded)
    except ValueError as e:
        print(f"[-] 16진수 변환 오류: {e}", file=sys.stderr)
        return ""
    
    derived_key = ""
    # C = P ^ K 이므로 K = C ^ P 입니다.
    for i in range(len(known_plaintext)):
        derived_key += chr(encrypted_bytes[start_index + i] ^ ord(known_plaintext[i]))
    
    return derived_key

def xor_decrypt(hex_encoded, key):
    """유도된 키를 사용하여 암호문 전체를 복호화합니다."""
    try:
        encrypted_bytes = bytes.fromhex(hex_encoded)
    except ValueError as e:
        print(f"[-] 16진수 변환 오류: {e}", file=sys.stderr)
        return ""
        
    decrypted_message = ""
    # 키 길이(KEY_LENGTH=5)만큼 반복하여 XOR을 수행합니다.
    for i in range(len(encrypted_bytes)):
        decrypted_message += chr(encrypted_bytes[i] ^ ord(key[i % len(key)]))
        
    return decrypted_message

# --- 3. 문제 해결 메인 함수 ---

def solve_challenge():
    """서버와 통신하고 키를 유도하여 문제를 해결하는 주 함수입니다."""
    print("==========================================")
    print("📢 XOR Plaintext Attack Auto Solver 시작")
    print(f"[*] 목표: {HOST}:{PORT}")
    print("==========================================")
    
    # 1. 서버 연결 및 데이터 수신
    print("\n[단계 1: 서버 연결 및 암호문 수신]")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        s.settimeout(1)
        
        # 서버 응답 수신 (데이터를 모두 읽을 때까지 대기)
        response = b''
        try:
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass # 타임아웃 발생 시 다음 단계로 진행
            
        response_str = response.decode()
        print(f"[+] 서버로부터 받은 원본 응답:\n{response_str.strip()}")

        # 정규 표현식으로 암호문 추출
        match = re.search(r'flag \d: ([0-9a-fA-F]+)', response_str)
        if not match:
            print("[-] 암호문 추출 실패. 서버 응답 형식을 확인하세요.", file=sys.stderr)
            s.close()
            return

        hex_encoded = match.group(1)
        print(f"[*] 추출된 암호문 (Hex): {hex_encoded}")

    except Exception as e:
        print(f"[-] 연결 또는 수신 오류: {e}", file=sys.stderr)
        return
    
    # 2. 키 유도 과정 (wise.py 출력 과정 재현)
    print("\n[단계 2: 키 유도 로직 실행 (wise.py 재현)]")
    
    # 2-1. 시작 평문('THM{')을 사용하여 키의 시작 부분 유도
    derived_key_start = derive_key_part(hex_encoded, KNOWN_START_PLAINTEXT, 0)
    print("Derived start of the key:", derived_key_start)

    # 2-2. 끝 평문('}')을 사용하여 키의 마지막 부분 유도
    # len(hex_encoded) // 2 는 바이트 길이(43)입니다. -1 을 하면 마지막 바이트 인덱스가 됩니다.
    derived_key_end = derive_key_part(hex_encoded, KNOWN_END_PLAINTEXT, len(hex_encoded) // 2 - 1)
    print("Derived end of the key:", derived_key_end)

    # 2-3. 최종 5바이트 키 유도
    # derived_key_full은 5 바이트 키가 반복되는 형태의 앞부분과 뒷부분을 연결합니다.
    derived_key_full = (derived_key_start + derived_key_end)
    derived_key = derived_key_full[0:KEY_LENGTH]
    print("Derived key:", derived_key)

    # 2-4. 유도된 키로 복호화 메시지 출력
    decrypted_message = xor_decrypt(hex_encoded, derived_key)
    print("Decrypted message:", decrypted_message)

    # 3. 키 전송 및 최종 응답 수신
    print("\n[단계 3: 유도된 키 전송 및 결과 확인]")
    key_to_send = derived_key + '\n' # 서버가 Enter 키 입력을 기다리므로 '\n' 추가
    print(f"[*] 전송하는 키: {derived_key}")
    s.sendall(key_to_send.encode())
    
    # 최종 응답 수신
    final_response = s.recv(1024).decode()
    print(f"[+] 최종 서버 응답:\n{final_response.strip()}")

    if "THM" in final_response or "flag" in final_response.lower() or "correct" in final_response.lower():
        print("🎉 SUCCESS! 플래그 획득에 성공했습니다.")
    elif "Nope" in final_response or "Close" in final_response:
        print("[-] FAILURE! 서버가 키를 거부했습니다. (다음 시도를 위해 스크립트를 다시 실행하세요.)")
    
    s.close()
    print("==========================================")


if __name__ == '__main__':
    solve_challenge()
```



┌──(kali㉿kali)-[~]
└─$ sudo python3 ./wise.py                                                                                 
==========================================
📢 XOR Plaintext Attack Auto Solver 시작
[*] 목표: 10.65.154.119:1337
==========================================

[단계 1: 서버 연결 및 암호문 수신]
[+] 서버로부터 받은 원본 응답:
This XOR encoded text has flag 1: 17181c2c3d72313d393906282516393764323c2e023e23642c2f1c283f18312428673831281e2530
What is the encryption key?
[*] 추출된 암호문 (Hex): 17181c2c3d72313d393906282516393764323c2e023e23642c2f1c283f18312428673831281e2530

[단계 2: 키 유도 로직 실행 (wise.py 재현)]
Derived start of the key: CPQW
Derived end of the key: M
Derived key: CPQWM
Decrypted message: THM{p1alntExtAtt4ckcAnr3alLyhUrty0urxOr}

[단계 3: 유도된 키 전송 및 결과 확인]
[*] 전송하는 키: CPQWM
[+] 최종 서버 응답:
Congrats! That is the correct key! Here is flag 2: THM{BrUt3_ForC1nG_XOR_cAn_B3_FuN_nO?}
🎉 SUCCESS! 플래그 획득에 성공했습니다.
==========================================
