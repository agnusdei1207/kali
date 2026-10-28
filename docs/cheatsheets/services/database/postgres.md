# PostgreSQL 기본 명령어 정리

## 1. 접속 및 기본 설정

```bash
# PostgreSQL 접속
psql -U username -d database_name
psql -U username -h hostname -p 5432 -d database_name

# 로컬 접속 (기본 사용자)
psql postgres
psql -U postgres

# 원격 접속
psql -U username -h 192.168.1.100 -p 5432 -d mydb

# 특정 DB로 직접 접속
psql -d database_name

# SSL 연결
psql "postgresql://username:password@hostname:5432/database?sslmode=require"
```

## 2. psql 내부 명령어 (백슬래시 명령어)

```sql
-- 도움말
\?
\h [SQL명령어]

-- 데이터베이스 관련
\l                    -- 데이터베이스 목록
\c database_name      -- 데이터베이스 연결/변경
\conninfo             -- 현재 연결 정보

-- 테이블 관련
\dt                   -- 테이블 목록
\d table_name         -- 테이블 구조 보기
\d+                   -- 모든 테이블 상세 정보
\dn                   -- 스키마 목록
\df                   -- 함수 목록
\dv                   -- 뷰 목록

-- 사용자 및 권한
\du                   -- 사용자 목록
\dp                   -- 테이블 권한 정보

-- 시스템
\timing               -- 쿼리 실행 시간 표시 토글
\x                    -- 확장 출력 모드 토글
\q                    -- 종료
```

## 3. 데이터베이스 관리 (DDL)

```sql
-- 데이터베이스 생성
CREATE DATABASE mydb;
CREATE DATABASE mydb OWNER username;
CREATE DATABASE mydb ENCODING 'UTF8';

-- 데이터베이스 삭제
DROP DATABASE mydb;

-- 현재 데이터베이스 확인
SELECT current_database();

-- 데이터베이스 목록 (SQL)
SELECT datname FROM pg_database;

-- 데이터베이스 크기
SELECT pg_size_pretty(pg_database_size('database_name'));
```

## 4. 스키마 관리

```sql
-- 스키마 생성
CREATE SCHEMA schema_name;

-- 스키마 삭제
DROP SCHEMA schema_name CASCADE;

-- 현재 스키마 확인
SELECT current_schema();

-- 스키마 목록
SELECT schema_name FROM information_schema.schemata;

-- 검색 경로 설정
SET search_path TO schema_name, public;
SHOW search_path;
```

## 5. 테이블 관리 (DDL)

```sql
-- 테이블 생성
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE,
    age INTEGER CHECK (age >= 0),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 테이블 삭제
DROP TABLE table_name;
DROP TABLE IF EXISTS table_name;

-- 테이블 구조 변경
ALTER TABLE users ADD COLUMN phone VARCHAR(20);
ALTER TABLE users DROP COLUMN phone;
ALTER TABLE users ALTER COLUMN email TYPE TEXT;
ALTER TABLE users ALTER COLUMN username SET NOT NULL;

-- 테이블 이름 변경
ALTER TABLE old_table RENAME TO new_table;

-- 컬럼 이름 변경
ALTER TABLE users RENAME COLUMN old_name TO new_name;
```

## 6. 데이터 조작 (DML)

### SELECT - 데이터 조회

```sql
-- 기본 조회
SELECT * FROM users;
SELECT username, email FROM users;

-- 조건부 조회
SELECT * FROM users WHERE age > 18;
SELECT * FROM users WHERE username LIKE '%kim%';
SELECT * FROM users WHERE id IN (1, 2, 3);
SELECT * FROM users WHERE created_at BETWEEN '2023-01-01' AND '2023-12-31';

-- 정규식 검색
SELECT * FROM users WHERE email ~ '.*@gmail\.com$';
SELECT * FROM users WHERE username ~* 'john';  -- 대소문자 무시

-- 정렬 및 제한
SELECT * FROM users ORDER BY created_at DESC;
SELECT * FROM users ORDER BY age ASC, username DESC;
SELECT * FROM users LIMIT 10;
SELECT * FROM users LIMIT 10 OFFSET 20;

-- DISTINCT
SELECT DISTINCT city FROM users;
SELECT DISTINCT ON (city) city, username FROM users;
```

### INSERT - 데이터 삽입

```sql
-- 단일 행 삽입
INSERT INTO users (username, email, age) VALUES ('john', 'john@email.com', 25);

-- 다중 행 삽입
INSERT INTO users (username, email, age) VALUES
    ('alice', 'alice@email.com', 30),
    ('bob', 'bob@email.com', 28);

-- 서브쿼리로 삽입
INSERT INTO users (username, email)
SELECT name, email FROM temp_users WHERE active = true;

-- RETURNING 절 (삽입된 데이터 반환)
INSERT INTO users (username, email) VALUES ('charlie', 'charlie@email.com')
RETURNING id, created_at;

-- ON CONFLICT (UPSERT)
INSERT INTO users (username, email) VALUES ('john', 'john@new.com')
ON CONFLICT (username) DO UPDATE SET email = EXCLUDED.email;
```

### UPDATE - 데이터 수정

```sql
-- 조건부 수정
UPDATE users SET email = 'newemail@email.com' WHERE id = 1;
UPDATE users SET age = age + 1 WHERE created_at < '2023-01-01';

-- 다중 컬럼 수정
UPDATE users SET username = 'newname', email = 'newemail@email.com' WHERE id = 1;

-- 서브쿼리 사용
UPDATE users SET city = (SELECT city FROM addresses WHERE addresses.user_id = users.id);

-- RETURNING 절
UPDATE users SET age = 30 WHERE username = 'john' RETURNING id, age;
```

### DELETE - 데이터 삭제

```sql
-- 조건부 삭제
DELETE FROM users WHERE id = 1;
DELETE FROM users WHERE created_at < '2022-01-01';

-- RETURNING 절
DELETE FROM users WHERE age < 18 RETURNING username, age;

-- 모든 데이터 삭제
DELETE FROM users;
TRUNCATE TABLE users;  -- 더 빠름, AUTO_INCREMENT 리셋
TRUNCATE TABLE users RESTART IDENTITY;  -- SERIAL 값도 리셋
```

## 7. 집계 함수 및 그룹화

```sql
-- 기본 집계 함수
SELECT COUNT(*) FROM users;
SELECT COUNT(DISTINCT email) FROM users;
SELECT SUM(price) FROM products;
SELECT AVG(age) FROM users;
SELECT MAX(price), MIN(price) FROM products;

-- 문자열 집계
SELECT STRING_AGG(username, ', ') FROM users;
SELECT ARRAY_AGG(username) FROM users;

-- GROUP BY
SELECT status, COUNT(*) FROM orders GROUP BY status;
SELECT city, AVG(age) FROM users GROUP BY city;
SELECT DATE_TRUNC('month', created_at), COUNT(*)
FROM users
GROUP BY DATE_TRUNC('month', created_at);

-- HAVING
SELECT city, COUNT(*)
FROM users
GROUP BY city
HAVING COUNT(*) > 5;

-- ROLLUP과 CUBE
SELECT city, status, COUNT(*)
FROM users
GROUP BY ROLLUP(city, status);

SELECT city, status, COUNT(*)
FROM users
GROUP BY CUBE(city, status);
```

## 8. 조인 (JOIN)

```sql
-- INNER JOIN
SELECT u.username, o.order_date
FROM users u
INNER JOIN orders o ON u.id = o.user_id;

-- LEFT JOIN
SELECT u.username, o.order_date
FROM users u
LEFT JOIN orders o ON u.id = o.user_id;

-- RIGHT JOIN
SELECT u.username, o.order_date
FROM users u
RIGHT JOIN orders o ON u.id = o.user_id;

-- FULL OUTER JOIN
SELECT u.username, o.order_date
FROM users u
FULL OUTER JOIN orders o ON u.id = o.user_id;

-- CROSS JOIN
SELECT u.username, p.product_name
FROM users u
CROSS JOIN products p;
```

## 9. 서브쿼리 및 CTE

```sql
-- WHERE 절 서브쿼리
SELECT * FROM users
WHERE id IN (SELECT user_id FROM orders WHERE amount > 100);

-- FROM 절 서브쿼리
SELECT avg_price.category, avg_price.average
FROM (
    SELECT category, AVG(price) as average
    FROM products
    GROUP BY category
) as avg_price;

-- CTE (Common Table Expression)
WITH high_value_orders AS (
    SELECT user_id, SUM(amount) as total
    FROM orders
    WHERE amount > 100
    GROUP BY user_id
)
SELECT u.username, h.total
FROM users u
JOIN high_value_orders h ON u.id = h.user_id;

-- 재귀 CTE
WITH RECURSIVE subordinates AS (
    SELECT id, name, manager_id FROM employees WHERE manager_id IS NULL
    UNION ALL
    SELECT e.id, e.name, e.manager_id
    FROM employees e
    JOIN subordinates s ON e.manager_id = s.id
)
SELECT * FROM subordinates;
```

## 10. 윈도우 함수

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
SELECT username, created_at,
    LAG(created_at) OVER (ORDER BY created_at) as prev_created,
    LEAD(created_at) OVER (ORDER BY created_at) as next_created
FROM users;

-- FIRST_VALUE, LAST_VALUE
SELECT username, age,
    FIRST_VALUE(username) OVER (ORDER BY age) as youngest,
    LAST_VALUE(username) OVER (ORDER BY age ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) as oldest
FROM users;
```

## 11. 트랜잭션 제어 (TCL)

```sql
-- 트랜잭션 시작
BEGIN;
START TRANSACTION;

-- 커밋
COMMIT;

-- 롤백
ROLLBACK;

-- 세이브포인트
SAVEPOINT my_savepoint;
ROLLBACK TO my_savepoint;
RELEASE SAVEPOINT my_savepoint;

-- 트랜잭션 격리 수준
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;
SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
```

## 12. 사용자 및 권한 관리 (DCL)

```sql
-- 사용자 생성
CREATE USER username WITH PASSWORD 'password';
CREATE USER username WITH ENCRYPTED PASSWORD 'password';

-- 사용자 속성
CREATE USER username WITH
    PASSWORD 'password'
    CREATEDB
    CREATEROLE
    LOGIN;

-- 권한 부여
GRANT ALL PRIVILEGES ON DATABASE mydb TO username;
GRANT SELECT, INSERT ON TABLE users TO username;
GRANT ALL ON SCHEMA public TO username;
GRANT USAGE ON SEQUENCE users_id_seq TO username;

-- 권한 확인
SELECT * FROM information_schema.role_table_grants WHERE grantee = 'username';

-- 권한 취소
REVOKE INSERT ON TABLE users FROM username;

-- 사용자 삭제
DROP USER username;

-- 역할(Role) 관리
CREATE ROLE readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;
GRANT readonly TO username;
```

## 13. 인덱스 관리

```sql
-- 인덱스 생성
CREATE INDEX idx_username ON users(username);
CREATE UNIQUE INDEX idx_email ON users(email);

-- 복합 인덱스
CREATE INDEX idx_name_age ON users(username, age);

-- 부분 인덱스
CREATE INDEX idx_active_users ON users(username) WHERE active = true;

-- 표현식 인덱스
CREATE INDEX idx_lower_email ON users(LOWER(email));

-- GIN 인덱스 (JSON, 배열용)
CREATE INDEX idx_tags ON posts USING GIN(tags);

-- 인덱스 확인
SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'users';

-- 인덱스 삭제
DROP INDEX idx_username;
```

## 14. JSON 데이터 처리

```sql
-- JSON 컬럼 생성
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    attributes JSONB
);

-- JSON 데이터 삽입
INSERT INTO products (name, attributes) VALUES
('Laptop', '{"brand": "Dell", "cpu": "Intel i7", "ram": "16GB"}');

-- JSON 데이터 조회
SELECT name, attributes->>'brand' as brand FROM products;
SELECT name, attributes->'specs'->>'cpu' as cpu FROM products;

-- JSON 경로 조회
SELECT name, attributes #> '{specs,cpu}' as cpu FROM products;

-- JSON 조건 검색
SELECT * FROM products WHERE attributes->>'brand' = 'Dell';
SELECT * FROM products WHERE attributes ? 'warranty';
SELECT * FROM products WHERE attributes @> '{"brand": "Dell"}';

-- JSON 집계
SELECT attributes->>'brand', COUNT(*)
FROM products
GROUP BY attributes->>'brand';
```

## 15. 배열 데이터 처리

```sql
-- 배열 컬럼 생성
CREATE TABLE posts (
    id SERIAL PRIMARY KEY,
    title VARCHAR(200),
    tags TEXT[]
);

-- 배열 데이터 삽입
INSERT INTO posts (title, tags) VALUES
('PostgreSQL Guide', ARRAY['database', 'postgresql', 'sql']);

-- 배열 데이터 조회
SELECT title, tags[1] as first_tag FROM posts;
SELECT title, array_length(tags, 1) as tag_count FROM posts;

-- 배열 검색
SELECT * FROM posts WHERE 'postgresql' = ANY(tags);
SELECT * FROM posts WHERE tags @> ARRAY['database'];
SELECT * FROM posts WHERE tags && ARRAY['sql', 'nosql'];

-- 배열 연산
SELECT title, array_append(tags, 'tutorial') FROM posts;
SELECT title, array_remove(tags, 'database') FROM posts;
```

## 16. 문자열 함수

```sql
-- 기본 문자열 함수
SELECT CONCAT(first_name, ' ', last_name) as full_name FROM users;
SELECT SUBSTRING(email FROM 1 FOR 5) FROM users;
SELECT LENGTH(username) FROM users;
SELECT UPPER(username), LOWER(email) FROM users;
SELECT TRIM(username) FROM users;
SELECT REPLACE(email, '@', ' at ') FROM users;

-- 정규식 함수
SELECT REGEXP_REPLACE(phone, '[^0-9]', '', 'g') FROM users;
SELECT REGEXP_SPLIT_TO_ARRAY(tags, ',') FROM posts;

-- 문자열 집계
SELECT STRING_AGG(username, ', ' ORDER BY username) FROM users;
```

## 17. 날짜/시간 함수

```sql
-- 현재 날짜/시간
SELECT NOW(), CURRENT_DATE, CURRENT_TIME;
SELECT CLOCK_TIMESTAMP(), TRANSACTION_TIMESTAMP();

-- 날짜 연산
SELECT NOW() + INTERVAL '1 day';
SELECT NOW() - INTERVAL '1 month';
SELECT AGE(NOW(), '1990-01-01');

-- 날짜 추출
SELECT EXTRACT(YEAR FROM created_at) FROM users;
SELECT DATE_PART('month', created_at) FROM users;
SELECT DATE_TRUNC('day', created_at) FROM users;

-- 날짜 포맷
SELECT TO_CHAR(created_at, 'YYYY-MM-DD') FROM users;
SELECT TO_DATE('2023-12-25', 'YYYY-MM-DD');
```

## 18. 시스템 정보 및 모니터링

```sql
-- 버전 정보
SELECT version();

-- 현재 연결 정보
SELECT * FROM pg_stat_activity;

-- 데이터베이스 통계
SELECT * FROM pg_stat_database;

-- 테이블 통계
SELECT * FROM pg_stat_user_tables;

-- 인덱스 사용 통계
SELECT * FROM pg_stat_user_indexes;

-- 테이블 크기
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables
WHERE schemaname = 'public';

-- 잠금 정보
SELECT * FROM pg_locks;

-- 설정 확인
SHOW ALL;
SHOW shared_buffers;
SHOW max_connections;
```

## 19. 백업 및 복구

```bash
# 데이터베이스 백업
pg_dump -U username -h hostname database_name > backup.sql
pg_dump -U username database_name -f backup.sql

# 압축 백업
pg_dump -U username database_name | gzip > backup.sql.gz

# 특정 테이블만 백업
pg_dump -U username -t table_name database_name > table_backup.sql

# 스키마만 백업
pg_dump -U username -s database_name > schema_backup.sql

# 바이너리 형식 백업 (빠름)
pg_dump -U username -Fc database_name -f backup.dump

# 백업 복구
psql -U username -d database_name -f backup.sql
pg_restore -U username -d database_name backup.dump

# 모든 데이터베이스 백업
pg_dumpall -U postgres > all_backup.sql
```

## 20. 성능 최적화

```sql
-- 쿼리 실행 계획
EXPLAIN SELECT * FROM users WHERE age > 25;
EXPLAIN ANALYZE SELECT * FROM users WHERE age > 25;
EXPLAIN (ANALYZE, BUFFERS) SELECT * FROM users WHERE age > 25;

-- 통계 정보 업데이트
ANALYZE;
ANALYZE table_name;

-- VACUUM (가비지 컬렉션)
VACUUM;
VACUUM ANALYZE;
VACUUM FULL table_name;

-- 자동 VACUUM 설정 확인
SELECT * FROM pg_stat_user_tables;

-- 느린 쿼리 로깅 설정
ALTER SYSTEM SET log_min_duration_statement = 1000;  -- 1초 이상
SELECT pg_reload_conf();
```

## 21. 확장 기능

```sql
-- 설치된 확장 확인
SELECT * FROM pg_extension;

-- 사용 가능한 확장 확인
SELECT * FROM pg_available_extensions;

-- 확장 설치
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "postgis";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- UUID 생성
SELECT uuid_generate_v4();

-- 전문 검색 (Full-text search)
CREATE EXTENSION IF NOT EXISTS "unaccent";
SELECT to_tsvector('english', 'The quick brown fox') @@ to_tsquery('english', 'fox');
```
