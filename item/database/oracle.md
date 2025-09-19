# Oracle 데이터베이스 기본 명령어 정리

## 1. 접속 및 기본 설정

```bash
# SQL*Plus 접속
sqlplus username/password@hostname:port/service_name
sqlplus username/password@//hostname:port/service_name
sqlplus username/password@tnsname

# SYS 사용자로 접속
sqlplus sys/password@hostname:port/service_name as sysdba
sqlplus / as sysdba  # 로컬에서 OS 인증

# 로컬 접속
sqlplus username/password
sqlplus / as sysdba

# SQL Developer나 기타 클라이언트 접속 문자열
username/password@hostname:port:sid
username/password@hostname:port/service_name
```

## 2. SQL\*Plus 기본 명령어

```sql
-- 도움말
HELP
HELP [명령어]

-- 환경 설정
SET PAGESIZE 100           -- 페이지당 라인 수
SET LINESIZE 200           -- 라인 길이
SET TIMING ON              -- 실행 시간 표시
SET AUTOCOMMIT ON          -- 자동 커밋
SET ECHO ON                -- 실행 명령어 표시

-- 화면 정리
CLEAR SCREEN
CL SCR

-- 스크립트 실행
@script_name.sql
@@script_name.sql          -- 현재 디렉토리 기준

-- 결과 파일로 출력
SPOOL output.txt
SELECT * FROM users;
SPOOL OFF

-- 종료
EXIT
QUIT
```

## 3. 사용자 및 스키마 관리

```sql
-- 현재 사용자 확인
SELECT USER FROM DUAL;
SHOW USER;

-- 모든 사용자 조회
SELECT username FROM dba_users;
SELECT username FROM all_users;

-- 사용자 생성
CREATE USER username IDENTIFIED BY password;
CREATE USER username IDENTIFIED BY password
DEFAULT TABLESPACE users
TEMPORARY TABLESPACE temp;

-- 사용자 비밀번호 변경
ALTER USER username IDENTIFIED BY new_password;

-- 사용자 삭제
DROP USER username;
DROP USER username CASCADE;  -- 스키마와 함께 삭제

-- 사용자 잠금/해제
ALTER USER username ACCOUNT LOCK;
ALTER USER username ACCOUNT UNLOCK;
```

## 4. 권한 관리 (DCL)

```sql
-- 시스템 권한 부여
GRANT CREATE SESSION TO username;
GRANT CREATE TABLE TO username;
GRANT CREATE VIEW TO username;
GRANT CREATE PROCEDURE TO username;
GRANT DBA TO username;  -- DBA 권한

-- 객체 권한 부여
GRANT SELECT ON table_name TO username;
GRANT INSERT, UPDATE, DELETE ON table_name TO username;
GRANT ALL ON table_name TO username;

-- 권한 확인
SELECT * FROM dba_sys_privs WHERE grantee = 'USERNAME';
SELECT * FROM dba_tab_privs WHERE grantee = 'USERNAME';
SELECT * FROM user_sys_privs;
SELECT * FROM user_tab_privs;

-- 권한 취소
REVOKE CREATE TABLE FROM username;
REVOKE SELECT ON table_name FROM username;

-- 역할(Role) 관리
CREATE ROLE role_name;
GRANT SELECT ANY TABLE TO role_name;
GRANT role_name TO username;
```

## 5. 테이블스페이스 관리

```sql
-- 테이블스페이스 조회
SELECT tablespace_name FROM dba_tablespaces;
SELECT tablespace_name, file_name FROM dba_data_files;

-- 테이블스페이스 생성
CREATE TABLESPACE ts_name
DATAFILE '/path/to/datafile.dbf' SIZE 100M
AUTOEXTEND ON NEXT 10M MAXSIZE 1G;

-- 테이블스페이스 삭제
DROP TABLESPACE ts_name INCLUDING CONTENTS AND DATAFILES;

-- 사용량 확인
SELECT
    tablespace_name,
    ROUND(SUM(bytes)/1024/1024, 2) as size_mb
FROM dba_data_files
GROUP BY tablespace_name;
```

## 6. 데이터베이스 객체 조회

```sql
-- 테이블 목록
SELECT table_name FROM user_tables;
SELECT table_name FROM all_tables;
SELECT table_name FROM dba_tables WHERE owner = 'SCHEMA_NAME';

-- 테이블 구조
DESCRIBE table_name;
DESC table_name;

-- 컬럼 정보
SELECT column_name, data_type, data_length, nullable
FROM user_tab_columns
WHERE table_name = 'TABLE_NAME';

-- 인덱스 정보
SELECT index_name, column_name FROM user_ind_columns
WHERE table_name = 'TABLE_NAME';

-- 제약조건 정보
SELECT constraint_name, constraint_type FROM user_constraints
WHERE table_name = 'TABLE_NAME';

-- 뷰 목록
SELECT view_name FROM user_views;

-- 시퀀스 목록
SELECT sequence_name FROM user_sequences;

-- 프로시저/함수 목록
SELECT object_name, object_type FROM user_objects
WHERE object_type IN ('PROCEDURE', 'FUNCTION', 'PACKAGE');
```

## 7. 테이블 관리 (DDL)

```sql
-- 테이블 생성
CREATE TABLE users (
    id NUMBER PRIMARY KEY,
    username VARCHAR2(50) NOT NULL,
    email VARCHAR2(100) UNIQUE,
    age NUMBER CHECK (age >= 0),
    created_date DATE DEFAULT SYSDATE
);

-- 시퀀스를 이용한 자동 증가
CREATE SEQUENCE users_seq START WITH 1 INCREMENT BY 1;

CREATE TABLE users (
    id NUMBER DEFAULT users_seq.NEXTVAL PRIMARY KEY,
    username VARCHAR2(50) NOT NULL
);

-- 테이블 수정
ALTER TABLE users ADD phone VARCHAR2(20);
ALTER TABLE users DROP COLUMN phone;
ALTER TABLE users MODIFY email VARCHAR2(200);
ALTER TABLE users RENAME COLUMN old_name TO new_name;

-- 테이블 이름 변경
RENAME old_table TO new_table;

-- 테이블 삭제
DROP TABLE table_name;
DROP TABLE table_name CASCADE CONSTRAINTS;  -- 제약조건과 함께
```

## 8. 데이터 조작 (DML)

### SELECT - 데이터 조회

```sql
-- 기본 조회
SELECT * FROM users;
SELECT username, email FROM users;

-- 조건부 조회
SELECT * FROM users WHERE age > 18;
SELECT * FROM users WHERE username LIKE '%kim%';
SELECT * FROM users WHERE id IN (1, 2, 3);
SELECT * FROM users WHERE created_date BETWEEN DATE '2023-01-01' AND DATE '2023-12-31';

-- 정규식 검색
SELECT * FROM users WHERE REGEXP_LIKE(email, '.*@gmail\.com$');

-- 정렬 및 제한
SELECT * FROM users ORDER BY created_date DESC;
SELECT * FROM users ORDER BY age ASC, username DESC;

-- ROWNUM 사용 (상위 N개)
SELECT * FROM users WHERE ROWNUM <= 10;
SELECT * FROM (SELECT * FROM users ORDER BY age DESC) WHERE ROWNUM <= 5;

-- Oracle 12c+ ROW LIMITING
SELECT * FROM users ORDER BY age DESC FETCH FIRST 10 ROWS ONLY;
SELECT * FROM users ORDER BY age DESC OFFSET 10 ROWS FETCH NEXT 5 ROWS ONLY;
```

### INSERT - 데이터 삽입

```sql
-- 단일 행 삽입
INSERT INTO users (id, username, email) VALUES (1, 'john', 'john@email.com');

-- 시퀀스 사용
INSERT INTO users (id, username, email) VALUES (users_seq.NEXTVAL, 'alice', 'alice@email.com');

-- 다중 행 삽입 (Oracle 23c+)
INSERT INTO users (id, username, email) VALUES
    (users_seq.NEXTVAL, 'bob', 'bob@email.com'),
    (users_seq.NEXTVAL, 'charlie', 'charlie@email.com');

-- INSERT ALL (다중 테이블 삽입)
INSERT ALL
    INTO users (id, username) VALUES (1, 'user1')
    INTO users (id, username) VALUES (2, 'user2')
SELECT * FROM dual;

-- 서브쿼리로 삽입
INSERT INTO users (username, email)
SELECT name, email FROM temp_users WHERE active = 'Y';
```

### UPDATE - 데이터 수정

```sql
-- 조건부 수정
UPDATE users SET email = 'newemail@email.com' WHERE id = 1;
UPDATE users SET age = age + 1 WHERE created_date < DATE '2023-01-01';

-- 다중 컬럼 수정
UPDATE users SET username = 'newname', email = 'newemail@email.com' WHERE id = 1;

-- 서브쿼리 사용
UPDATE users
SET city = (SELECT city FROM addresses WHERE addresses.user_id = users.id)
WHERE EXISTS (SELECT 1 FROM addresses WHERE addresses.user_id = users.id);

-- MERGE 문 (UPSERT)
MERGE INTO users u
USING (SELECT 1 as id, 'john' as username, 'john@new.com' as email FROM dual) s
ON (u.id = s.id)
WHEN MATCHED THEN UPDATE SET u.email = s.email
WHEN NOT MATCHED THEN INSERT (id, username, email) VALUES (s.id, s.username, s.email);
```

### DELETE - 데이터 삭제

```sql
-- 조건부 삭제
DELETE FROM users WHERE id = 1;
DELETE FROM users WHERE created_date < DATE '2022-01-01';

-- 모든 데이터 삭제
DELETE FROM users;
TRUNCATE TABLE users;  -- 빠름, 롤백 불가
```

## 9. 조인 (JOIN)

```sql
-- INNER JOIN
SELECT u.username, o.order_date
FROM users u
INNER JOIN orders o ON u.id = o.user_id;

-- LEFT OUTER JOIN
SELECT u.username, o.order_date
FROM users u
LEFT OUTER JOIN orders o ON u.id = o.user_id;

-- RIGHT OUTER JOIN
SELECT u.username, o.order_date
FROM users u
RIGHT OUTER JOIN orders o ON u.id = o.user_id;

-- FULL OUTER JOIN
SELECT u.username, o.order_date
FROM users u
FULL OUTER JOIN orders o ON u.id = o.user_id;

-- Oracle 전용 조인 문법 (Legacy)
SELECT u.username, o.order_date
FROM users u, orders o
WHERE u.id = o.user_id;

-- OUTER JOIN (+)
SELECT u.username, o.order_date
FROM users u, orders o
WHERE u.id = o.user_id(+);  -- LEFT OUTER JOIN
```

## 10. 집계 함수 및 그룹화

```sql
-- 기본 집계 함수
SELECT COUNT(*) FROM users;
SELECT COUNT(DISTINCT email) FROM users;
SELECT SUM(price) FROM products;
SELECT AVG(age) FROM users;
SELECT MAX(price), MIN(price) FROM products;

-- 문자열 집계 (Oracle 11g+)
SELECT LISTAGG(username, ', ') WITHIN GROUP (ORDER BY username) FROM users;

-- GROUP BY
SELECT status, COUNT(*) FROM orders GROUP BY status;
SELECT city, AVG(age) FROM users GROUP BY city;
SELECT EXTRACT(YEAR FROM created_date), COUNT(*)
FROM users
GROUP BY EXTRACT(YEAR FROM created_date);

-- HAVING
SELECT city, COUNT(*)
FROM users
GROUP BY city
HAVING COUNT(*) > 5;

-- ROLLUP, CUBE
SELECT city, status, COUNT(*)
FROM users
GROUP BY ROLLUP(city, status);

SELECT city, status, COUNT(*)
FROM users
GROUP BY CUBE(city, status);

-- GROUPING SETS
SELECT city, status, COUNT(*)
FROM users
GROUP BY GROUPING SETS ((city), (status), ());
```

## 11. 분석 함수 (윈도우 함수)

```sql
-- ROW_NUMBER, RANK, DENSE_RANK
SELECT username, age,
    ROW_NUMBER() OVER (ORDER BY age DESC) as row_num,
    RANK() OVER (ORDER BY age DESC) as rank,
    DENSE_RANK() OVER (ORDER BY age DESC) as dense_rank
FROM users;

-- PARTITION BY
SELECT username, city, age,
    ROW_NUMBER() OVER (PARTITION BY city ORDER BY age DESC) as city_rank
FROM users;

-- LAG, LEAD
SELECT username, created_date,
    LAG(created_date) OVER (ORDER BY created_date) as prev_created,
    LEAD(created_date) OVER (ORDER BY created_date) as next_created
FROM users;

-- FIRST_VALUE, LAST_VALUE
SELECT username, age,
    FIRST_VALUE(username) OVER (ORDER BY age) as youngest,
    LAST_VALUE(username) OVER (ORDER BY age ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) as oldest
FROM users;

-- SUM, AVG with OVER
SELECT username, salary,
    SUM(salary) OVER (ORDER BY salary) as running_total,
    AVG(salary) OVER (PARTITION BY department) as dept_avg
FROM employees;
```

## 12. 계층형 쿼리 (Hierarchical Query)

```sql
-- CONNECT BY 구문
SELECT LEVEL, LPAD(' ', LEVEL * 2) || name as hierarchy, id, parent_id
FROM employees
START WITH parent_id IS NULL
CONNECT BY PRIOR id = parent_id
ORDER SIBLINGS BY name;

-- 루트에서 리프까지 경로
SELECT SYS_CONNECT_BY_PATH(name, '/') as path, name
FROM employees
START WITH parent_id IS NULL
CONNECT BY PRIOR id = parent_id;

-- 사이클 감지
SELECT name, CONNECT_BY_ISCYCLE
FROM employees
START WITH parent_id IS NULL
CONNECT BY NOCYCLE PRIOR id = parent_id;
```

## 13. 트랜잭션 제어 (TCL)

```sql
-- 트랜잭션 시작 (암시적)
-- Oracle은 첫 번째 DML 문에서 자동으로 트랜잭션 시작

-- 커밋
COMMIT;

-- 롤백
ROLLBACK;

-- 세이브포인트
SAVEPOINT sp1;
ROLLBACK TO sp1;

-- 자동 커밋 설정
SET AUTOCOMMIT ON;
SET AUTOCOMMIT OFF;

-- 읽기 전용 트랜잭션
SET TRANSACTION READ ONLY;

-- 트랜잭션 격리 수준
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;
SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
```

## 14. 인덱스 관리

```sql
-- 인덱스 생성
CREATE INDEX idx_username ON users(username);
CREATE UNIQUE INDEX idx_email ON users(email);

-- 복합 인덱스
CREATE INDEX idx_name_age ON users(username, age);

-- 함수 기반 인덱스
CREATE INDEX idx_upper_username ON users(UPPER(username));

-- 비트맵 인덱스 (DW용)
CREATE BITMAP INDEX idx_status ON orders(status);

-- 파티션 인덱스
CREATE INDEX idx_part_date ON sales(sale_date) LOCAL;

-- 인덱스 정보 확인
SELECT index_name, column_name FROM user_ind_columns
WHERE table_name = 'USERS';

-- 인덱스 통계
SELECT index_name, blevel, leaf_blocks, distinct_keys
FROM user_indexes
WHERE table_name = 'USERS';

-- 인덱스 재구성
ALTER INDEX idx_username REBUILD;
ALTER INDEX idx_username REBUILD ONLINE;

-- 인덱스 삭제
DROP INDEX idx_username;
```

## 15. 시퀀스 관리

```sql
-- 시퀀스 생성
CREATE SEQUENCE seq_users
START WITH 1
INCREMENT BY 1
MAXVALUE 999999999
NOCACHE
NOCYCLE;

-- 시퀀스 사용
SELECT seq_users.NEXTVAL FROM dual;
SELECT seq_users.CURRVAL FROM dual;

-- 시퀀스 수정
ALTER SEQUENCE seq_users INCREMENT BY 10;
ALTER SEQUENCE seq_users MAXVALUE 9999999999;

-- 시퀀스 정보 확인
SELECT sequence_name, min_value, max_value, increment_by, last_number
FROM user_sequences;

-- 시퀀스 삭제
DROP SEQUENCE seq_users;
```

## 16. 뷰 관리

```sql
-- 뷰 생성
CREATE VIEW v_active_users AS
SELECT id, username, email
FROM users
WHERE status = 'ACTIVE';

-- 복합 뷰
CREATE VIEW v_user_orders AS
SELECT u.username, COUNT(o.id) as order_count
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.username;

-- 뷰 수정
CREATE OR REPLACE VIEW v_active_users AS
SELECT id, username, email, phone
FROM users
WHERE status = 'ACTIVE';

-- 뷰 정보 확인
SELECT view_name FROM user_views;
SELECT text FROM user_views WHERE view_name = 'V_ACTIVE_USERS';

-- 뷰 삭제
DROP VIEW v_active_users;
```

## 17. 함수 및 문자열 처리

```sql
-- 문자열 함수
SELECT CONCAT(first_name, last_name) as full_name FROM users;
SELECT SUBSTR(email, 1, 5) FROM users;
SELECT LENGTH(username) FROM users;
SELECT UPPER(username), LOWER(email) FROM users;
SELECT TRIM(username) FROM users;
SELECT REPLACE(email, '@', ' at ') FROM users;

-- 패딩
SELECT LPAD(id, 5, '0') FROM users;  -- 00001
SELECT RPAD(username, 10, '*') FROM users;

-- 정규식 함수
SELECT REGEXP_REPLACE(phone, '[^0-9]', '') FROM users;
SELECT REGEXP_SUBSTR(email, '[^@]+') as username_part FROM users;

-- CASE 문
SELECT username,
    CASE
        WHEN age < 18 THEN 'Minor'
        WHEN age BETWEEN 18 AND 65 THEN 'Adult'
        ELSE 'Senior'
    END as age_group
FROM users;

-- DECODE (Oracle 전용)
SELECT username,
    DECODE(status, 'A', 'Active', 'I', 'Inactive', 'Unknown') as status_desc
FROM users;

-- NULL 처리
SELECT username, NVL(phone, 'No phone') FROM users;
SELECT username, NVL2(phone, 'Has phone', 'No phone') FROM users;
SELECT username, COALESCE(phone, email, 'No contact') FROM users;
```

## 18. 날짜 함수

```sql
-- 현재 날짜/시간
SELECT SYSDATE FROM dual;  -- 현재 날짜시간
SELECT SYSTIMESTAMP FROM dual;  -- 타임존 포함
SELECT CURRENT_DATE FROM dual;
SELECT CURRENT_TIMESTAMP FROM dual;

-- 날짜 연산
SELECT SYSDATE + 1 FROM dual;  -- 1일 후
SELECT SYSDATE - 30 FROM dual;  -- 30일 전
SELECT ADD_MONTHS(SYSDATE, 3) FROM dual;  -- 3개월 후

-- 날짜 차이
SELECT SYSDATE - created_date as days_since FROM users;
SELECT MONTHS_BETWEEN(SYSDATE, created_date) as months_since FROM users;

-- 날짜 추출
SELECT EXTRACT(YEAR FROM created_date) FROM users;
SELECT EXTRACT(MONTH FROM created_date) FROM users;
SELECT TO_CHAR(created_date, 'YYYY') as year FROM users;

-- 날짜 포맷
SELECT TO_CHAR(SYSDATE, 'YYYY-MM-DD HH24:MI:SS') FROM dual;
SELECT TO_CHAR(SYSDATE, 'Day, DD Month YYYY') FROM dual;
SELECT TO_DATE('2023-12-25', 'YYYY-MM-DD') FROM dual;

-- 날짜 절단
SELECT TRUNC(SYSDATE, 'MONTH') FROM dual;  -- 월 첫날
SELECT TRUNC(SYSDATE, 'YEAR') FROM dual;   -- 연 첫날
```

## 19. PL/SQL 기본

```sql
-- 익명 블록
BEGIN
    DBMS_OUTPUT.PUT_LINE('Hello World');
END;
/

-- 변수 사용
DECLARE
    v_username VARCHAR2(50);
    v_count NUMBER;
BEGIN
    SELECT username INTO v_username FROM users WHERE id = 1;
    SELECT COUNT(*) INTO v_count FROM users;
    DBMS_OUTPUT.PUT_LINE('User: ' || v_username);
    DBMS_OUTPUT.PUT_LINE('Total users: ' || v_count);
END;
/

-- 조건문
DECLARE
    v_age NUMBER := 25;
BEGIN
    IF v_age < 18 THEN
        DBMS_OUTPUT.PUT_LINE('Minor');
    ELSIF v_age >= 65 THEN
        DBMS_OUTPUT.PUT_LINE('Senior');
    ELSE
        DBMS_OUTPUT.PUT_LINE('Adult');
    END IF;
END;
/

-- 반복문
BEGIN
    FOR i IN 1..10 LOOP
        DBMS_OUTPUT.PUT_LINE('Number: ' || i);
    END LOOP;
END;
/

-- 커서 사용
DECLARE
    CURSOR user_cursor IS SELECT username, email FROM users;
    v_username users.username%TYPE;
    v_email users.email%TYPE;
BEGIN
    OPEN user_cursor;
    LOOP
        FETCH user_cursor INTO v_username, v_email;
        EXIT WHEN user_cursor%NOTFOUND;
        DBMS_OUTPUT.PUT_LINE(v_username || ': ' || v_email);
    END LOOP;
    CLOSE user_cursor;
END;
/
```

## 20. 시스템 정보 및 모니터링

```sql
-- 인스턴스 정보
SELECT instance_name, version, status FROM v$instance;

-- 데이터베이스 정보
SELECT name, created, log_mode FROM v$database;

-- 세션 정보
SELECT sid, serial#, username, program, machine FROM v$session;

-- 현재 실행중인 SQL
SELECT sql_text FROM v$sql WHERE sql_id = '&sql_id';

-- 테이블 크기
SELECT segment_name, bytes/1024/1024 as size_mb
FROM user_segments
WHERE segment_type = 'TABLE';

-- 대기 이벤트
SELECT event, total_waits, time_waited FROM v$system_event ORDER BY time_waited DESC;

-- 잠금 정보
SELECT l.sid, l.type, l.lmode, l.request, o.object_name
FROM v$lock l, dba_objects o
WHERE l.id1 = o.object_id;

-- 파라미터 확인
SELECT name, value FROM v$parameter WHERE name LIKE '%memory%';
SHOW PARAMETER memory;

-- 통계 정보
SELECT table_name, num_rows, blocks, last_analyzed
FROM user_tables;
```

## 21. 백업 및 복구

```bash
# Export (논리적 백업)
exp userid=username/password@database file=backup.dmp tables=table1,table2
exp userid=username/password@database file=backup.dmp owner=schema_name
exp userid=system/password@database file=full_backup.dmp full=y

# Import (복구)
imp userid=username/password@database file=backup.dmp
imp userid=username/password@database file=backup.dmp tables=table1,table2

# Data Pump (Oracle 10g+)
expdp username/password@database directory=backup_dir dumpfile=backup.dmp schemas=schema_name
impdp username/password@database directory=backup_dir dumpfile=backup.dmp schemas=schema_name

# RMAN (물리적 백업)
rman target /
BACKUP DATABASE;
BACKUP TABLESPACE users;
BACKUP DATAFILE 1;
```

## 22. 성능 최적화

```sql
-- 실행 계획
EXPLAIN PLAN FOR SELECT * FROM users WHERE age > 25;
SELECT * FROM TABLE(DBMS_XPLAN.DISPLAY);

-- 통계 수집
EXEC DBMS_STATS.GATHER_TABLE_STATS('SCHEMA_NAME', 'TABLE_NAME');
EXEC DBMS_STATS.GATHER_SCHEMA_STATS('SCHEMA_NAME');

-- AWR 보고서 생성
SELECT snap_id, begin_interval_time FROM dba_hist_snapshot ORDER BY snap_id DESC;
@$ORACLE_HOME/rdbms/admin/awrrpt.sql

-- SQL 튜닝 어드바이저
DECLARE
    task_name VARCHAR2(30) := 'sql_tuning_task';
BEGIN
    DBMS_SQLTUNE.CREATE_TUNING_TASK(
        sql_text => 'SELECT * FROM users WHERE age > 25',
        task_name => task_name
    );
    DBMS_SQLTUNE.EXECUTE_TUNING_TASK(task_name);
END;
/

-- 힌트 사용
SELECT /*+ INDEX(users, idx_age) */ * FROM users WHERE age > 25;
SELECT /*+ FULL(users) */ * FROM users WHERE age > 25;
```

## 23. 파티셔닝

```sql
-- 범위 파티션
CREATE TABLE sales (
    sale_id NUMBER,
    sale_date DATE,
    amount NUMBER
)
PARTITION BY RANGE (sale_date) (
    PARTITION sales_2023 VALUES LESS THAN (DATE '2024-01-01'),
    PARTITION sales_2024 VALUES LESS THAN (DATE '2025-01-01'),
    PARTITION sales_future VALUES LESS THAN (MAXVALUE)
);

-- 해시 파티션
CREATE TABLE customers (
    customer_id NUMBER,
    name VARCHAR2(100)
)
PARTITION BY HASH (customer_id) PARTITIONS 4;

-- 파티션 정보 확인
SELECT table_name, partition_name, high_value
FROM user_tab_partitions;

-- 파티션 추가
ALTER TABLE sales ADD PARTITION sales_2025 VALUES LESS THAN (DATE '2026-01-01');

-- 파티션 삭제
ALTER TABLE sales DROP PARTITION sales_2023;
```
