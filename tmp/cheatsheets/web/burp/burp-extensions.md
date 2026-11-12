# Burp 확장: Autorize, Logger++, Turbo Intruder

- Burp 확장(jar)을 Extender에서 로드해 기능을 늘리는 문서. Autorize는 인가 우회 자동 검증, Logger++는 전체 요청 로깅·검색, Turbo Intruder는 파이썬 스크립트 기반 고속 공격을 담당한다.
- 고·저 권한 세션의 인가 차이를 자동 비교할 때, 요청 이력을 조건 검색해 흔적을 찾을 때, Intruder 스로틀을 벗어난 대량·레이스 공격이 필요할 때.
- 각 확장의 jar 필요(BApp Store 또는 GitHub release). Burp의 Extender 탭에서 로드. Turbo Intruder는 Jython 스크립트를 쓴다.

## 확장 로딩 방법 (공통)

```text
1. Extender 탭 > Extensions > Add
2. Extension type: Java 선택 후 jar 파일 지정 (python 확장이면 .py)
3. 로드되면 상단 탭(또는 하단 탭)에 확장 UI가 나타난다
```

- workspace\web\burp\extensions\ 아래 jar 예시: autorize.jar, LoggerPlusPlus.jar, turbo-intruder-all.jar

## Autorize (인가 우회 검증)

- 저권한(일반 사용자) 쿠키를 Autorize 탭의 Configuration > Changed Requests에 등록한다.
- 고권한 계정으로 프록시를 통해 요청을 보내면 Autorize가 같은 요청을 저권한 세션으로 재전송해 결과를 비교한다.
- Enforcement status: bypassed(빨강)면 저권한으로도 접근 성공, 즉 인가 결함 후보다.

```text
흐름: 저권한 쿠키 등록 -> 고권한으로 기능 사용 -> Autorize 표에서 빨간 bypassed 확인
     -> 해당 요청을 Repeater로 보내 수동 재검증
```

- Filters에서 3xx 리다이렉트·정적 리소스를 제외해 노이즈를 줄인다.

## Logger++ (로깅·검색)

- 모든 Burp 도구의 요청·응답을 테이블로 기록한다.
- 하단 검색에서 필드(REQ, RESP, LEN, STATUS 등)별 정규식 검색. 예: `REQ CONTAINS "admin"`.
- Fields 탭에서 사용자 정의 열(정규식 추출)을 만들 수 있고, 로그를 CSV로 내보낸다.
- 토큰·시크릿 흔적, 특정 파라미터가 등장한 모든 요소 추적에 유용하다.

## Turbo Intruder (파이썬 스크립트 공격)

- 대상 요청 우클릭 -> Extensions > Turbo Intruder > Send to turbo intruder.
- 공격 로직을 파이썬으로 작성해 engine.queue로 대량 요청을 큐잉한다. HTTP 파이프라이닝·HTTP/2 지원으로 Intruder보다 훨씬 빠르다.

```python
# examples/race-single-packet-attack.py 참고
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=1,
                           pipeline=False)
    for i in range(30):
        engine.queue(target.req, target.baseInput)

def handleResponse(target, user, response):
    target.completed(user)
```

- 레이스 컨디션(동시 요청)과 대규모 사전 공격 모두에 쓰이며, 스크립트에서 파일을 열어 큐잉도 가능하다.

## 팁·트러블슈팅

1. 확장 로드 실패는 Burp Java 버전 문제가 흔하다. 최신 Burp + 확장 조합으로 맞춘다.
2. Autorize의 빨간 결과는 응답이 우연히 유사한 경우도 있으니 반드시 Repeater로 재확인한다.
3. Turbo Intruder 스크립트 오류는 콘솔(Output/Errors)에 기록된다. Jython(파이썬 2 계열) 문법에 맞춘다.
