# MySQL 기본 명령어 정리

## 1. 접속 및 기본 설정

```bash
# MySQL 접속
mysql -u username -p
mysql -u username -p -h hostname
mysql -u username -p database_name

# 원격 접속
mysql -u username -p -h 192.168.1.100 -P 3306

# 루트 접속
mysql -u root -p
```

## 2. 데이터베이스 관리 (DDL)

```sql
-- 데이터베이스 목록 보기
SHOW DATABASES;

-- 데이터베이스 생성
CREATE DATABASE database_name;

-- 데이터베이스 선택
USE database_name;

-- 데이터베이스 삭제
DROP DATABASE database_name;

-- 현재 선택된 데이터베이스 확인
SELECT DATABASE();
```

## 3. 테이블 관리 (DDL)

```sql
-- 테이블 목록 보기
SHOW TABLES;

-- 테이블 구조 보기
DESCRIBE table_name;
DESC table_name;
SHOW COLUMNS FROM table_name;

-- 테이블 생성
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 테이블 삭제
DROP TABLE table_name;

-- 테이블 구조 변경
ALTER TABLE table_name ADD COLUMN new_column VARCHAR(50);
ALTER TABLE table_name DROP COLUMN column_name;
ALTER TABLE table_name MODIFY COLUMN column_name VARCHAR(100);
```

## 4. 데이터 조작 (DML)

### SELECT - 데이터 조회

```sql
-- 기본 조회
SELECT * FROM table_name;
SELECT column1, column2 FROM table_name;

-- 조건부 조회
SELECT * FROM users WHERE age > 18;
SELECT * FROM users WHERE name LIKE '%kim%';
SELECT * FROM users WHERE id IN (1, 2, 3);
SELECT * FROM users WHERE created_at BETWEEN '2023-01-01' AND '2023-12-31';

-- 정렬
SELECT * FROM users ORDER BY created_at DESC;
SELECT * FROM users ORDER BY age ASC, name DESC;

-- 제한
SELECT * FROM users LIMIT 10;
SELECT * FROM users LIMIT 10, 20; -- OFFSET 10, LIMIT 20
```

### INSERT - 데이터 삽입

```sql
-- 단일 행 삽입
INSERT INTO users (username, email) VALUES ('john', 'john@email.com');

-- 다중 행 삽입
INSERT INTO users (username, email) VALUES
    ('alice', 'alice@email.com'),
    ('bob', 'bob@email.com');

-- 모든 컬럼 삽입
INSERT INTO users VALUES (1, 'charlie', 'charlie@email.com', NOW());
```

### UPDATE - 데이터 수정

```sql
-- 조건부 수정
UPDATE users SET email = 'newemail@email.com' WHERE id = 1;
UPDATE users SET age = age + 1 WHERE created_at < '2023-01-01';

-- 다중 컬럼 수정
UPDATE users SET username = 'newname', email = 'newemail@email.com' WHERE id = 1;
```

### DELETE - 데이터 삭제

```sql
-- 조건부 삭제
DELETE FROM users WHERE id = 1;
DELETE FROM users WHERE created_at < '2022-01-01';

-- 모든 데이터 삭제 (테이블 구조 유지)
DELETE FROM users;
TRUNCATE TABLE users; -- 더 빠름
```

## 5. 집계 함수 및 그룹화

```sql
-- 기본 집계 함수
SELECT COUNT(*) FROM users;
SELECT COUNT(DISTINCT email) FROM users;
SELECT SUM(price) FROM products;
SELECT AVG(age) FROM users;
SELECT MAX(price), MIN(price) FROM products;

-- GROUP BY
SELECT status, COUNT(*) FROM orders GROUP BY status;
SELECT category, AVG(price) FROM products GROUP BY category;
SELECT YEAR(created_at), MONTH(created_at), COUNT(*)
FROM users
GROUP BY YEAR(created_at), MONTH(created_at);

-- HAVING (그룹 조건)
SELECT category, COUNT(*)
FROM products
GROUP BY category
HAVING COUNT(*) > 5;

SELECT status, SUM(amount)
FROM orders
GROUP BY status
HAVING SUM(amount) > 1000;
```

## 6. 조인 (JOIN)

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

-- 다중 테이블 조인
SELECT u.username, o.order_date, p.product_name
FROM users u
INNER JOIN orders o ON u.id = o.user_id
INNER JOIN products p ON o.product_id = p.id;
```

## 7. 서브쿼리

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

-- EXISTS
SELECT * FROM users u
WHERE EXISTS (SELECT 1 FROM orders o WHERE o.user_id = u.id);
```

## 8. 트랜잭션 제어 (TCL)

```sql
-- 트랜잭션 시작
START TRANSACTION;
BEGIN;

-- 커밋
COMMIT;

-- 롤백
ROLLBACK;

-- 세이브포인트
SAVEPOINT savepoint_name;
ROLLBACK TO savepoint_name;
```

## 9. 사용자 및 권한 관리 (DCL)

```sql
-- 사용자 생성
CREATE USER 'username'@'localhost' IDENTIFIED BY 'password';
CREATE USER 'username'@'%' IDENTIFIED BY 'password';

-- 권한 부여
GRANT ALL PRIVILEGES ON database_name.* TO 'username'@'localhost';
GRANT SELECT, INSERT ON table_name TO 'username'@'localhost';

-- 권한 확인
SHOW GRANTS FOR 'username'@'localhost';

-- 권한 취소
REVOKE INSERT ON database_name.table_name FROM 'username'@'localhost';

-- 사용자 삭제
DROP USER 'username'@'localhost';

-- 권한 새로고침
FLUSH PRIVILEGES;
```

## 10. 인덱스 관리

```sql
-- 인덱스 생성
CREATE INDEX idx_username ON users(username);
CREATE UNIQUE INDEX idx_email ON users(email);

-- 복합 인덱스
CREATE INDEX idx_name_age ON users(username, age);

-- 인덱스 확인
SHOW INDEX FROM table_name;

-- 인덱스 삭제
DROP INDEX idx_username ON users;
```

## 11. 시스템 정보 및 상태

```sql
-- 현재 사용자 확인
SELECT USER();
SELECT CURRENT_USER();

-- 버전 확인
SELECT VERSION();

-- 프로세스 목록
SHOW PROCESSLIST;

-- 상태 확인
SHOW STATUS;
SHOW VARIABLES;

-- 테이블 상태
SHOW TABLE STATUS;

-- 데이터베이스 크기
SELECT
    table_schema AS 'Database',
    SUM(data_length + index_length) / 1024 / 1024 AS 'Size (MB)'
FROM information_schema.tables
GROUP BY table_schema;
```

## 12. 문자열 함수

```sql
-- 문자열 함수
SELECT CONCAT(first_name, ' ', last_name) as full_name FROM users;
SELECT SUBSTRING(email, 1, 5) FROM users;
SELECT LENGTH(username) FROM users;
SELECT UPPER(username), LOWER(email) FROM users;
SELECT TRIM(username) FROM users;
SELECT REPLACE(email, '@', ' at ') FROM users;
```

## 13. 날짜 함수

```sql
-- 현재 날짜/시간
SELECT NOW(), CURDATE(), CURTIME();

-- 날짜 연산
SELECT DATE_ADD(NOW(), INTERVAL 1 DAY);
SELECT DATE_SUB(NOW(), INTERVAL 1 MONTH);
SELECT DATEDIFF('2023-12-31', '2023-01-01');

-- 날짜 포맷
SELECT DATE_FORMAT(created_at, '%Y-%m-%d') FROM users;
SELECT YEAR(created_at), MONTH(created_at), DAY(created_at) FROM users;
```

## 14. 조건문

```sql
-- CASE WHEN
SELECT username,
    CASE
        WHEN age < 18 THEN 'Minor'
        WHEN age BETWEEN 18 AND 65 THEN 'Adult'
        ELSE 'Senior'
    END as age_group
FROM users;

-- IF 함수
SELECT username, IF(age >= 18, 'Adult', 'Minor') as status FROM users;

-- IFNULL, COALESCE
SELECT username, IFNULL(phone, 'No phone') FROM users;
SELECT username, COALESCE(phone, email, 'No contact') FROM users;
```

## 15. 백업 및 복구

```bash
# 데이터베이스 백업
mysqldump -u username -p database_name > backup.sql
mysqldump -u username -p --all-databases > all_backup.sql

# 특정 테이블 백업
mysqldump -u username -p database_name table_name > table_backup.sql

# 백업 복구
mysql -u username -p database_name < backup.sql
mysql -u username -p < all_backup.sql
```

## 16. 자주 사용하는 정보 스키마 쿼리

```sql
-- 모든 테이블 정보
SELECT table_name, table_rows, data_length
FROM information_schema.tables
WHERE table_schema = 'database_name';

-- 컬럼 정보
SELECT column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_schema = 'database_name' AND table_name = 'table_name';

-- 인덱스 정보
SELECT table_name, index_name, column_name
FROM information_schema.statistics
WHERE table_schema = 'database_name';
```
