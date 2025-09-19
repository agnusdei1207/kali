# SQLite 기본 명령어 정리

## 1. 접속 및 기본 설정

```bash
# SQLite 데이터베이스 열기/생성
sqlite3 database.db

# 메모리 데이터베이스
sqlite3 :memory:

# 읽기 전용 모드
sqlite3 -readonly database.db

# SQL 명령어 직접 실행
sqlite3 database.db "SELECT * FROM users;"

# CSV 파일에서 데이터 가져오기
sqlite3 database.db ".mode csv" ".import data.csv table_name"

# 스크립트 파일 실행
sqlite3 database.db < script.sql
sqlite3 database.db ".read script.sql"
```

## 2. SQLite 셸 명령어 (dot commands)

```sql
-- 도움말
.help
.help [command]

-- 데이터베이스 정보
.databases          -- 연결된 데이터베이스 목록
.dbinfo             -- 데이터베이스 정보
.schema             -- 모든 테이블 스키마
.schema table_name  -- 특정 테이블 스키마

-- 테이블 정보
.tables             -- 테이블 목록
.tables pattern     -- 패턴과 일치하는 테이블
.indexes            -- 인덱스 목록
.indexes table_name -- 특정 테이블의 인덱스

-- 출력 형식 설정
.mode csv           -- CSV 형식
.mode column        -- 컬럼 형식
.mode html          -- HTML 형식
.mode insert        -- INSERT 문 형식
.mode json          -- JSON 형식
.mode line          -- 라인별 형식
.mode list          -- 리스트 형식 (기본)
.mode table         -- 테이블 형식
.mode tabs          -- 탭 구분 형식

-- 헤더 및 구분자 설정
.headers on         -- 컬럼 헤더 표시
.headers off        -- 컬럼 헤더 숨김
.separator ","      -- 구분자 설정

-- 출력 설정
.width 10 20 15     -- 컬럼 너비 설정
.output file.txt    -- 파일로 출력
.output stdout      -- 표준 출력으로 되돌림

-- 파일 작업
.save backup.db     -- 메모리 DB를 파일로 저장
.restore backup.db  -- 파일에서 메모리 DB로 복원
.backup backup.db   -- 현재 DB 백업
.read script.sql    -- SQL 스크립트 실행

-- 데이터 가져오기/내보내기
.import file.csv table_name  -- CSV 파일 가져오기
.dump                        -- 전체 DB를 SQL로 덤프
.dump table_name            -- 특정 테이블 덤프

-- 시스템 명령
.system command     -- 시스템 명령어 실행
.shell command      -- 셸 명령어 실행
.cd directory       -- 디렉토리 변경
.pwd               -- 현재 디렉토리 표시

-- 종료
.exit
.quit
```

## 3. 데이터 타입

```sql
-- SQLite 데이터 타입 (동적 타입 시스템)
-- NULL: NULL 값
-- INTEGER: 정수 (1, 2, 3, 4, 6, 8바이트)
-- REAL: 부동소수점 (8바이트)
-- TEXT: 문자열 (UTF-8, UTF-16)
-- BLOB: 바이너리 데이터

-- 타입 선호도 (Type Affinity)
CREATE TABLE example (
    id INTEGER PRIMARY KEY,     -- INTEGER 선호
    name TEXT,                  -- TEXT 선호
    price REAL,                 -- REAL 선호
    data BLOB,                  -- BLOB 선호
    created_date NUMERIC        -- NUMERIC 선호 (INTEGER, REAL, TEXT 순)
);
```

## 4. 테이블 관리 (DDL)

```sql
-- 테이블 생성
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT,
    age INTEGER CHECK (age >= 0),
    created_date TEXT DEFAULT CURRENT_TIMESTAMP,
    is_active INTEGER DEFAULT 1  -- SQLite에는 BOOLEAN이 없음 (0/1 사용)
);

-- ROWID 테이블 (기본)
CREATE TABLE simple_table (
    name TEXT,
    value INTEGER
);
-- 자동으로 rowid 컬럼 생성됨

-- WITHOUT ROWID 테이블
CREATE TABLE key_value (
    key TEXT PRIMARY KEY,
    value TEXT
) WITHOUT ROWID;

-- 임시 테이블
CREATE TEMPORARY TABLE temp_data (
    id INTEGER,
    data TEXT
);

-- 테이블 존재 확인 후 생성
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT
);

-- 테이블 이름 변경
ALTER TABLE users RENAME TO customers;

-- 컬럼 추가 (SQLite 3.2.0+)
ALTER TABLE users ADD COLUMN phone TEXT;

-- 컬럼 이름 변경 (SQLite 3.25.0+)
ALTER TABLE users RENAME COLUMN old_name TO new_name;

-- 컬럼 삭제 (SQLite 3.35.0+)
ALTER TABLE users DROP COLUMN phone;

-- 테이블 삭제
DROP TABLE users;
DROP TABLE IF EXISTS users;
```

## 5. 제약조건

```sql
-- PRIMARY KEY
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT
);

-- 복합 PRIMARY KEY
CREATE TABLE user_roles (
    user_id INTEGER,
    role_id INTEGER,
    PRIMARY KEY (user_id, role_id)
);

-- UNIQUE
CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    sku TEXT UNIQUE,
    name TEXT
);

-- FOREIGN KEY (활성화 필요)
PRAGMA foreign_keys = ON;

CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    product_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- CHECK 제약조건
CREATE TABLE employees (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    age INTEGER CHECK (age BETWEEN 18 AND 65),
    salary REAL CHECK (salary > 0),
    email TEXT CHECK (email LIKE '%@%.%')
);

-- DEFAULT 값
CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    level TEXT DEFAULT 'INFO'
);
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
SELECT * FROM users WHERE created_date BETWEEN '2023-01-01' AND '2023-12-31';

-- GLOB 패턴 매칭 (대소문자 구분)
SELECT * FROM users WHERE username GLOB '*[Kk]im*';

-- 정규식 (확장 필요)
-- SELECT * FROM users WHERE username REGEXP '^[A-Z]';

-- 정렬 및 제한
SELECT * FROM users ORDER BY created_date DESC;
SELECT * FROM users ORDER BY age ASC, username DESC;
SELECT * FROM users LIMIT 10;
SELECT * FROM users LIMIT 10 OFFSET 20;

-- DISTINCT
SELECT DISTINCT city FROM users;

-- CASE 문
SELECT username,
    CASE
        WHEN age < 18 THEN 'Minor'
        WHEN age BETWEEN 18 AND 65 THEN 'Adult'
        ELSE 'Senior'
    END as age_group
FROM users;

-- NULL 처리
SELECT username, COALESCE(phone, email, 'No contact') as contact FROM users;
SELECT username, IFNULL(phone, 'No phone') FROM users;
```

### INSERT - 데이터 삽입

```sql
-- 단일 행 삽입
INSERT INTO users (username, email, age) VALUES ('john', 'john@email.com', 25);

-- 다중 행 삽입
INSERT INTO users (username, email, age) VALUES
    ('alice', 'alice@email.com', 30),
    ('bob', 'bob@email.com', 28);

-- 모든 컬럼 삽입
INSERT INTO users VALUES (1, 'charlie', 'charlie@email.com', 35, datetime('now'), 1);

-- INSERT OR IGNORE (중복 무시)
INSERT OR IGNORE INTO users (username, email) VALUES ('john', 'john@email.com');

-- INSERT OR REPLACE (UPSERT)
INSERT OR REPLACE INTO users (id, username, email) VALUES (1, 'john_updated', 'john@new.com');

-- 서브쿼리로 삽입
INSERT INTO users (username, email)
SELECT name, email FROM temp_users WHERE active = 1;

-- 마지막 삽입된 ROWID 확인
INSERT INTO users (username, email) VALUES ('david', 'david@email.com');
SELECT last_insert_rowid();
```

### UPDATE - 데이터 수정

```sql
-- 기본 수정
UPDATE users SET email = 'newemail@email.com' WHERE id = 1;
UPDATE users SET age = age + 1 WHERE created_date < '2023-01-01';

-- 다중 컬럼 수정
UPDATE users SET username = 'newname', email = 'newemail@email.com' WHERE id = 1;

-- UPDATE OR IGNORE
UPDATE OR IGNORE users SET username = 'duplicate' WHERE id = 1;

-- 조인을 이용한 수정 (서브쿼리 사용)
UPDATE users
SET city = (SELECT city FROM addresses WHERE addresses.user_id = users.id)
WHERE EXISTS (SELECT 1 FROM addresses WHERE addresses.user_id = users.id);
```

### DELETE - 데이터 삭제

```sql
-- 조건부 삭제
DELETE FROM users WHERE id = 1;
DELETE FROM users WHERE created_date < '2022-01-01';

-- 모든 데이터 삭제
DELETE FROM users;

-- VACUUM으로 공간 정리
VACUUM;
```

## 7. 조인 (JOIN)

```sql
-- INNER JOIN
SELECT u.username, o.order_date
FROM users u
INNER JOIN orders o ON u.id = o.user_id;

-- LEFT JOIN
SELECT u.username, o.order_date
FROM users u
LEFT JOIN orders o ON u.id = o.user_id;

-- CROSS JOIN
SELECT u.username, p.product_name
FROM users u
CROSS JOIN products p;

-- NATURAL JOIN
SELECT username, order_date
FROM users
NATURAL JOIN orders;

-- 다중 테이블 조인
SELECT u.username, o.order_date, p.product_name
FROM users u
INNER JOIN orders o ON u.id = o.user_id
INNER JOIN products p ON o.product_id = p.id;
```

## 8. 집계 함수 및 그룹화

```sql
-- 기본 집계 함수
SELECT COUNT(*) FROM users;
SELECT COUNT(DISTINCT email) FROM users;
SELECT SUM(price) FROM products;
SELECT AVG(age) FROM users;
SELECT MAX(price), MIN(price) FROM products;

-- 문자열 집계
SELECT GROUP_CONCAT(username) FROM users;
SELECT GROUP_CONCAT(username, ', ') FROM users;
SELECT GROUP_CONCAT(DISTINCT city) FROM users;

-- GROUP BY
SELECT status, COUNT(*) FROM orders GROUP BY status;
SELECT city, AVG(age) FROM users GROUP BY city;
SELECT strftime('%Y', created_date), COUNT(*)
FROM users
GROUP BY strftime('%Y', created_date);

-- HAVING
SELECT city, COUNT(*)
FROM users
GROUP BY city
HAVING COUNT(*) > 5;

-- 복잡한 그룹화
SELECT
    strftime('%Y-%m', created_date) as month,
    COUNT(*) as user_count,
    AVG(age) as avg_age
FROM users
GROUP BY strftime('%Y-%m', created_date)
ORDER BY month;
```

## 9. 윈도우 함수 (SQLite 3.25.0+)

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

-- 누적 합계
SELECT username, salary,
    SUM(salary) OVER (ORDER BY salary ROWS UNBOUNDED PRECEDING) as running_total
FROM employees;
```

## 10. CTE (Common Table Expression) - SQLite 3.8.3+

```sql
-- 기본 CTE
WITH high_value_orders AS (
    SELECT user_id, SUM(amount) as total
    FROM orders
    WHERE amount > 100
    GROUP BY user_id
)
SELECT u.username, h.total
FROM users u
INNER JOIN high_value_orders h ON u.id = h.user_id;

-- 재귀 CTE
WITH RECURSIVE cnt(x) AS (
    SELECT 1
    UNION ALL
    SELECT x + 1 FROM cnt WHERE x < 10
)
SELECT x FROM cnt;

-- 계층형 데이터
WITH RECURSIVE employee_hierarchy AS (
    SELECT id, name, manager_id, 1 as level
    FROM employees
    WHERE manager_id IS NULL

    UNION ALL

    SELECT e.id, e.name, e.manager_id, eh.level + 1
    FROM employees e
    INNER JOIN employee_hierarchy eh ON e.manager_id = eh.id
)
SELECT * FROM employee_hierarchy ORDER BY level, name;
```

## 11. 트랜잭션 제어 (TCL)

```sql
-- 트랜잭션 시작
BEGIN;
BEGIN TRANSACTION;
BEGIN IMMEDIATE;     -- 즉시 잠금
BEGIN EXCLUSIVE;     -- 배타적 잠금

-- 커밋
COMMIT;
COMMIT TRANSACTION;
END;
END TRANSACTION;

-- 롤백
ROLLBACK;
ROLLBACK TRANSACTION;

-- 세이브포인트
SAVEPOINT sp1;
ROLLBACK TO sp1;
RELEASE sp1;

-- 자동 커밋 모드 확인
PRAGMA auto_vacuum;
```

## 12. 인덱스 관리

```sql
-- 인덱스 생성
CREATE INDEX idx_username ON users(username);
CREATE UNIQUE INDEX idx_email ON users(email);

-- 복합 인덱스
CREATE INDEX idx_name_age ON users(username, age);

-- 부분 인덱스
CREATE INDEX idx_active_users ON users(username) WHERE is_active = 1;

-- 표현식 인덱스
CREATE INDEX idx_lower_username ON users(LOWER(username));

-- 인덱스 정보 확인
.indexes users
SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'users';

-- 인덱스 분석
ANALYZE;
ANALYZE table_name;

-- 인덱스 삭제
DROP INDEX idx_username;
DROP INDEX IF EXISTS idx_username;
```

## 13. 뷰 관리

```sql
-- 뷰 생성
CREATE VIEW v_active_users AS
SELECT id, username, email
FROM users
WHERE is_active = 1;

-- 임시 뷰
CREATE TEMPORARY VIEW v_temp AS
SELECT * FROM users WHERE age > 18;

-- 뷰 목록
SELECT name FROM sqlite_master WHERE type = 'view';

-- 뷰 정의 확인
SELECT sql FROM sqlite_master WHERE type = 'view' AND name = 'v_active_users';

-- 뷰 삭제
DROP VIEW v_active_users;
DROP VIEW IF EXISTS v_active_users;
```

## 14. 트리거

```sql
-- INSERT 트리거
CREATE TRIGGER tr_users_insert
AFTER INSERT ON users
FOR EACH ROW
BEGIN
    INSERT INTO audit_log (table_name, action, user_id, timestamp)
    VALUES ('users', 'INSERT', NEW.id, datetime('now'));
END;

-- UPDATE 트리거
CREATE TRIGGER tr_users_update
AFTER UPDATE ON users
FOR EACH ROW
WHEN OLD.email != NEW.email
BEGIN
    INSERT INTO audit_log (table_name, action, user_id, old_value, new_value, timestamp)
    VALUES ('users', 'UPDATE', NEW.id, OLD.email, NEW.email, datetime('now'));
END;

-- DELETE 트리거
CREATE TRIGGER tr_users_delete
BEFORE DELETE ON users
FOR EACH ROW
BEGIN
    INSERT INTO deleted_users SELECT * FROM users WHERE id = OLD.id;
END;

-- INSTEAD OF 트리거 (뷰용)
CREATE TRIGGER tr_view_insert
INSTEAD OF INSERT ON v_user_summary
FOR EACH ROW
BEGIN
    INSERT INTO users (username, email) VALUES (NEW.username, NEW.email);
END;

-- 트리거 목록
SELECT name FROM sqlite_master WHERE type = 'trigger';

-- 트리거 삭제
DROP TRIGGER tr_users_insert;
```

## 15. JSON 지원 (SQLite 3.45.0+)

```sql
-- JSON 함수들
SELECT json('{"name": "John", "age": 30}');
SELECT json_valid('{"name": "John"}');  -- 1 (valid)

-- JSON 데이터 추출
SELECT json_extract('{"name": "John", "age": 30}', '$.name');
SELECT json_extract('{"users": [{"name": "John"}, {"name": "Alice"}]}', '$.users[0].name');

-- JSON 데이터 수정
SELECT json_set('{"name": "John", "age": 30}', '$.age', 31);
SELECT json_insert('{"name": "John"}', '$.age', 30);
SELECT json_remove('{"name": "John", "age": 30}', '$.age');

-- JSON 배열 함수
SELECT json_array_length('[1, 2, 3, 4]');  -- 4
SELECT json_each.value FROM json_each('[1, 2, 3]');

-- 테이블에서 JSON 사용
CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT,
    attributes TEXT  -- JSON 데이터
);

INSERT INTO products VALUES (1, 'Laptop', '{"brand": "Dell", "cpu": "Intel i7"}');

SELECT name, json_extract(attributes, '$.brand') as brand FROM products;
```

## 16. 전문 검색 (FTS - Full Text Search)

```sql
-- FTS 테이블 생성
CREATE VIRTUAL TABLE docs USING fts5(title, content);

-- 데이터 삽입
INSERT INTO docs VALUES ('SQLite Guide', 'This is a comprehensive guide to SQLite database');
INSERT INTO docs VALUES ('Python Tutorial', 'Learn Python programming language');

-- 전문 검색
SELECT * FROM docs WHERE docs MATCH 'SQLite';
SELECT * FROM docs WHERE docs MATCH 'guide OR tutorial';
SELECT * FROM docs WHERE docs MATCH 'Python AND programming';

-- 구문 검색
SELECT * FROM docs WHERE docs MATCH '"SQLite database"';

-- 근접 검색
SELECT * FROM docs WHERE docs MATCH 'comprehensive NEAR guide';

-- 하이라이팅
SELECT highlight(docs, 0, '<b>', '</b>') as title FROM docs WHERE docs MATCH 'SQLite';

-- FTS 스니펫
SELECT snippet(docs, 1, '<mark>', '</mark>', '...', 10) as excerpt
FROM docs WHERE docs MATCH 'guide';
```

## 17. 문자열 함수

```sql
-- 기본 문자열 함수
SELECT username || ' (' || email || ')' as display_name FROM users;
SELECT SUBSTR(email, 1, 5) FROM users;
SELECT LENGTH(username) FROM users;
SELECT UPPER(username), LOWER(email) FROM users;
SELECT TRIM(username) FROM users;
SELECT REPLACE(email, '@', ' at ') FROM users;

-- 문자열 검색
SELECT * FROM users WHERE INSTR(email, 'gmail') > 0;
SELECT * FROM users WHERE email LIKE '%@gmail.com';

-- 문자열 패딩
SELECT PRINTF('%05d', id) as padded_id FROM users;  -- 00001
SELECT PRINTF('%-10s', username) as padded_name FROM users;

-- 문자열 분할 (간단한 방법)
WITH RECURSIVE split(word, str) AS (
    SELECT '', 'apple,banana,orange'||','
    UNION ALL
    SELECT
        SUBSTR(str, 0, INSTR(str, ',')),
        SUBSTR(str, INSTR(str, ',')+1)
    FROM split WHERE str != ''
)
SELECT word FROM split WHERE word != '';
```

## 18. 날짜/시간 함수

```sql
-- 현재 날짜/시간
SELECT datetime('now');           -- 현재 UTC 시간
SELECT datetime('now', 'localtime'); -- 로컬 시간
SELECT date('now');               -- 현재 날짜만
SELECT time('now');               -- 현재 시간만

-- Unix 타임스탬프
SELECT strftime('%s', 'now');     -- Unix 타임스탬프
SELECT datetime(1640995200, 'unixepoch'); -- Unix 타임스탬프를 날짜로

-- 날짜 연산
SELECT datetime('now', '+1 day');     -- 1일 후
SELECT datetime('now', '-3 months');  -- 3개월 전
SELECT datetime('now', '+1 year', '-1 day'); -- 1년 후 하루 전

-- 날짜 포맷
SELECT strftime('%Y-%m-%d', 'now');           -- 2023-12-25
SELECT strftime('%Y-%m-%d %H:%M:%S', 'now');  -- 2023-12-25 14:30:00
SELECT strftime('%w', 'now');                 -- 요일 (0=일요일)
SELECT strftime('%j', 'now');                 -- 연중 일 번호

-- 날짜 차이 계산
SELECT julianday('2023-12-31') - julianday('2023-01-01') as days_diff;

-- 특정 날짜 생성
SELECT date('2023-12-25');
SELECT datetime('2023-12-25 14:30:00');

-- 날짜 유효성 검사
SELECT datetime('2023-02-29');  -- NULL (invalid)
SELECT datetime('2024-02-29');  -- valid
```

## 19. PRAGMA 문 (SQLite 설정)

```sql
-- 데이터베이스 정보
PRAGMA database_list;
PRAGMA table_info(users);
PRAGMA table_list;
PRAGMA index_list(users);
PRAGMA index_info(idx_username);

-- 외래키 설정
PRAGMA foreign_keys = ON;
PRAGMA foreign_keys;  -- 현재 설정 확인

-- 저널 모드
PRAGMA journal_mode = WAL;  -- Write-Ahead Logging
PRAGMA journal_mode = DELETE;
PRAGMA journal_mode;

-- 동기화 모드
PRAGMA synchronous = FULL;   -- 안전
PRAGMA synchronous = NORMAL; -- 기본값
PRAGMA synchronous = OFF;    -- 빠름, 위험

-- 캐시 크기
PRAGMA cache_size = 10000;   -- 페이지 수
PRAGMA cache_size = -64000;  -- KB 단위 (음수)

-- 임시 저장소
PRAGMA temp_store = MEMORY;  -- 메모리 사용
PRAGMA temp_store = FILE;    -- 파일 사용

-- Auto Vacuum
PRAGMA auto_vacuum = FULL;
PRAGMA auto_vacuum = INCREMENTAL;
PRAGMA auto_vacuum = NONE;

-- 페이지 크기
PRAGMA page_size = 4096;

-- 무결성 검사
PRAGMA integrity_check;
PRAGMA quick_check;

-- 컴파일 옵션
PRAGMA compile_options;

-- 버전 정보
SELECT sqlite_version();
```

## 20. 성능 최적화

```sql
-- 쿼리 실행 계획
EXPLAIN QUERY PLAN SELECT * FROM users WHERE age > 25;
EXPLAIN SELECT * FROM users WHERE age > 25;

-- 통계 수집
ANALYZE;
ANALYZE users;

-- 인덱스 힌트 (SQLite는 자동 최적화)
-- 대신 INDEXED BY 구문 사용
SELECT * FROM users INDEXED BY idx_username WHERE username = 'john';

-- 컴파일된 문 캐시
PRAGMA cache_size = 20000;

-- WAL 모드로 성능 향상
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

-- 대량 삽입 최적화
BEGIN TRANSACTION;
-- 많은 INSERT 문들
COMMIT;

-- 메모리 매핑 I/O
PRAGMA mmap_size = 268435456;  -- 256MB
```

## 21. 백업 및 복구

```sql
-- SQL 덤프로 백업
.dump > backup.sql
.dump users > users_backup.sql

-- 바이너리 백업
.backup backup.db

-- CSV로 내보내기
.mode csv
.headers on
.output users.csv
SELECT * FROM users;
.output stdout

-- CSV에서 가져오기
.mode csv
.import users.csv users

-- 메모리 DB를 파일로 저장
.save backup.db

-- 파일 DB를 메모리로 복원
.restore backup.db

-- VACUUM으로 최적화
VACUUM;
VACUUM INTO 'optimized.db';
```

## 22. 데이터베이스 암호화 (SQLCipher 확장)

```sql
-- 암호화된 데이터베이스 생성
PRAGMA key = 'your_password';

-- 기존 DB 암호화
ATTACH DATABASE 'encrypted.db' AS encrypted KEY 'your_password';
SELECT sqlcipher_export('encrypted');
DETACH DATABASE encrypted;

-- 암호 변경
PRAGMA rekey = 'new_password';

-- 암호화 상태 확인
PRAGMA cipher_version;
```

## 23. 확장 및 사용자 정의 함수

```sql
-- 확장 로드
.load extension_name

-- 수학 함수 (확장 필요)
-- SELECT SQRT(16);
-- SELECT POW(2, 3);
-- SELECT SIN(3.14159);

-- 사용자 정의 집계 함수 (애플리케이션에서 구현)
-- 예: Python sqlite3 모듈에서
-- conn.create_aggregate("stdev", 1, StdevFunc)

-- 가상 테이블
-- CREATE VIRTUAL TABLE email_fts USING fts5(content);
```

## 24. 시스템 정보 및 메타데이터

```sql
-- 마스터 테이블 (모든 객체 정보)
SELECT * FROM sqlite_master;
SELECT type, name, sql FROM sqlite_master WHERE type = 'table';

-- 임시 객체 정보
SELECT * FROM sqlite_temp_master;

-- 컴파일 정보
SELECT sqlite_version();
SELECT sqlite_source_id();
PRAGMA compile_options;

-- 데이터베이스 크기
SELECT page_count * page_size as size_bytes FROM pragma_page_count(), pragma_page_size();

-- 테이블 크기 정보
SELECT name, SUM("pgsize") as size
FROM dbstat
WHERE name IS NOT NULL
GROUP BY name
ORDER BY size DESC;

-- 연결 정보
.databases
.tables
.schema

-- 성능 통계 (확장 필요)
-- SELECT * FROM pragma_stats;
```

## 25. 일반적인 작업 예제

```sql
-- 중복 제거
DELETE FROM users WHERE rowid NOT IN (
    SELECT MIN(rowid) FROM users GROUP BY email
);

-- 페이징
SELECT * FROM users ORDER BY id LIMIT 10 OFFSET 20;

-- 랜덤 레코드
SELECT * FROM users ORDER BY RANDOM() LIMIT 5;

-- 조건부 업데이트 (UPSERT)
INSERT INTO stats (date, count) VALUES ('2023-12-25', 1)
ON CONFLICT(date) DO UPDATE SET count = count + 1;

-- 피벗 테이블 (간단한 버전)
SELECT
    product_name,
    SUM(CASE WHEN month = 'Jan' THEN sales ELSE 0 END) as Jan,
    SUM(CASE WHEN month = 'Feb' THEN sales ELSE 0 END) as Feb,
    SUM(CASE WHEN month = 'Mar' THEN sales ELSE 0 END) as Mar
FROM monthly_sales
GROUP BY product_name;

-- 연속된 일련번호 생성
WITH RECURSIVE series(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM series WHERE n < 100
)
SELECT n FROM series;
```
