# mitmproxy 실전 요약 메모

## 1. 설치

```bash
sudo apt install mitmproxy
```

## 2. 프록시 실행

```bash
mitmproxy -p 8080
```

- 기본 HTTP 프록시 포트: 8080
- 터미널 UI 조작:

  - ↑↓ : 요청 탐색
  - → : 상세 보기
  - e : 수정 (Edit)
  - a : 전송 (Accept)
  - q : 종료

---

## 3. 프록시에 curl 물리기

```bash
curl -x http://127.0.0.1:8080 http://target.thm
```

- `-x`: 프록시 지정
- `http`, `ffuf`, `nikto`, `wpscan` 등 다 적용 가능

---

## 4. 헤더 조작 (curl)

```bash
curl -x http://127.0.0.1:8080 http://target.thm \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "User-Agent: hacker"
```

- WAF 우회 시 `X-Forwarded-For`, `User-Agent`, `Host` 많이 사용

---

## 5. 요청 저장

```bash
mitmproxy -p 8080 -w log.mitm
```

- 추후 분석용 로그 저장

---

## 6. 저장된 요청 재생

```bash
mitmproxy -re log.mitm
```

---

## 7. 자주 쓰는 필터 (mitmproxy 내에서 입력)

| 목적        | 명령어            |
| ----------- | ----------------- |
| 특정 호스트 | `~h "target.thm"` |
| GET만 보기  | `~m GET`          |
| POST만 보기 | `~m POST`         |
| 특정 URL    | `~u "/admin"`     |

---

## 8. 요청 수정 예시 (실전 활용)

1. curl로 요청
2. mitmproxy에서 해당 요청 선택
3. `e` 누르고 헤더/URL/파라미터 수정
4. `a`로 전송

---

```

```
