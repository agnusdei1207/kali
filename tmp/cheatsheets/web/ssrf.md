# SSRF

서버 측 요청 위조 취약점 점검 내용입니다.

## 테스트

```bash
http://target?url=http://internal-host
http://target?url=file:///etc/passwd
```
