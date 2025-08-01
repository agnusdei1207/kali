```bash
apt install mitmproxy -y

mitmproxy --mode regular -p 8080

mitmproxy --mode regular -p 8080 --no-http2
# --no-http2: HTTP/2 문제 방지 (중요)

curl -x 127.0.0.1:8080 http://10.10.184.121/login.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "username=admin&password=1234"
```
