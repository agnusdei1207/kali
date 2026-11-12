# Arjun을 이용한 숨은 HTTP 파라미터 발견

- Arjun — 엔드포인트가 받는 숨은 GET/POST 파라미터를 워드리스트로 추리는 도구. 없는 파라미터와 있는 파라미터의 응답 차이(상태 코드, 본문 해시 등)를 비교해 진짜 파라미터를 가려낸다.
- API 엔드포인트에 파라미터 힌트가 없을 때. admin=true 같은 숨은 스위치를 찾을 때. JS 파일·외부 소스에서 파라미터를 패시브로 수집할 때(--passive).
- kali: sudo apt install arjun. 공식 설치는 python3 -m pipx install arjun 경로다. 대상마다 요청 수가 천 단위까지 늘어나므로 rate 옵션을 반드시 조절한다.

## 기본 사용법

```bash
arjun -u https://example.com/api/users
arjun -u https://example.com/api/users -m POST
arjun -u https://example.com/api -m JSON
```

## 주요 옵션

- `-u`: 대상 URL(엔드포인트 단위).
- `-m GET/POST/JSON/XML`: 요청 방식. JSON은 application/json 바디로 테스트한다.
- `-w small|medium|large`: 내장 워드리스트 선택. 파일 경로도 된다(기본 워드리스트 약 2.6만 개).
- `-t 5`: 스레드 수(기본 2).
- `--stable`: 안정 모드. 스레드 1 + 6~12초 무작위 딜레이. rate limit에 자주 막히는 대상용.
- `--ratelimit 2`: 초당 요청 수 제한.
- `-d 2`: 요청 간 고정 딜레이(초). 지정하면 스레드가 1로 강제된다.
- `-T 10`: 타임아웃(기본 15초).
- `-oJ result.json` / `-oT result.txt` / `-oB 127.0.0.1:8080`: JSON·텍스트·BurpSuite로 결과 내보내기.
- `--passive example.com`: 요청 없이 JS·외부 소스에서 파라미터만 수집.
- `-i targets.txt`: 대상 목록 파일 입력.

## 실전 예시

```bash
# rate limit이 빡빡한 API
arjun -u https://example.com/api/v2/search -m POST --ratelimit 2 -oJ found.json

# 느리지만 안전한 스캔
arjun -u https://example.com/api/v2/search --stable

# 대상 여러 개 한꺼번에
arjun -i targets.txt -t 5 -oT found.txt
```

## 팁과 트러블슈팅

- 결과가 비어 있어도 놓친 게 아닐 수 있다. -w medium에서 large로 워드리스트를 늘려 재시도한다.
- 429·403이 계속 나오면 --stable 또는 --ratelimit를 내린다. 한번 차단당하면 이후 스캔 전체가 막힌다.
- JSON API는 -m JSON으로 테스트해야 한다. form-인코딩 POST와 응답이 달라지므로 두 방식을 각각 돌려본다.
- 찾은 파라미터는 ffuf로 값 퍼징(예: role=FUZZ)에 이어 붙인다.
