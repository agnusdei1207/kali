# Microsoft SQL Server (MSSQL) 기본 명령어 정리

## 1. 접속 및 기본 설정

```bash
# sqlcmd 접속 (Windows)
sqlcmd -S server_name -U username -P password
sqlcmd -S localhost -U sa -P password
sqlcmd -S server_name\instance_name -U username -P password

# Windows 인증 접속
sqlcmd -S server_name -E

# 특정 데이터베이스로 접속
sqlcmd -S server_name -U username -P password -d database_name

# 신뢰할 수 있는 연결 (Trusted Connection)
sqlcmd -S server_name -T

# 원격 접속
sqlcmd -S 192.168.1.100 -U username -P password

# 포트 지정 접속
sqlcmd -S server_name,1433 -U username -P password
```

## 2. sqlcmd 기본 명령어

```sql
-- 도움말
:help
:?

-- 쿼리 실행
SELECT * FROM users;
GO

-- 파일에서 스크립트 실행
:r script.sql
GO

-- 결과를 파일로 출력
:out output.txt
SELECT * FROM users;
GO
:out

-- 변수 설정
:setvar username "john"
SELECT * FROM users WHERE username = '$(username)';
GO

-- 연결 정보 확인
:listvar

-- 종료
:quit
:exit
```

## 3. 데이터베이스 관리

```sql
-- 데이터베이스 목록
SELECT name FROM sys.databases;

-- 현재 데이터베이스 확인
SELECT DB_NAME();

-- 데이터베이스 생성
CREATE DATABASE MyDatabase;

-- 데이터베이스 생성 (상세 옵션)
CREATE DATABASE MyDatabase
ON (
    NAME = 'MyDatabase_Data',
    FILENAME = 'C:\Data\MyDatabase.mdf',
    SIZE = 100MB,
    MAXSIZE = 1GB,
    FILEGROWTH = 10MB
)
LOG ON (
    NAME = 'MyDatabase_Log',
    FILENAME = 'C:\Data\MyDatabase.ldf',
    SIZE = 10MB,
    MAXSIZE = 100MB,
    FILEGROWTH = 10%
);

-- 데이터베이스 사용
USE MyDatabase;

-- 데이터베이스 삭제
DROP DATABASE MyDatabase;

-- 데이터베이스 상태 확인
SELECT name, state_desc FROM sys.databases;

-- 데이터베이스 크기 확인
SELECT
    DB_NAME(database_id) AS DatabaseName,
    Name AS Logical_Name,
    Physical_Name,
    (size*8)/1024 AS SizeMB
FROM sys.master_files;
```

## 4. 스키마 관리

```sql
-- 스키마 목록
SELECT name FROM sys.schemas;

-- 스키마 생성
CREATE SCHEMA sales;

-- 스키마 삭제
DROP SCHEMA sales;

-- 현재 스키마 확인
SELECT SCHEMA_NAME();

-- 기본 스키마 변경
ALTER USER username WITH DEFAULT_SCHEMA = sales;
```

## 5. 테이블 관리 (DDL)

```sql
-- 테이블 목록
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';
SELECT name FROM sys.tables;

-- 테이블 구조 확인
EXEC sp_help 'table_name';
EXEC sp_columns 'table_name';

-- 컬럼 정보
SELECT
    COLUMN_NAME,
    DATA_TYPE,
    CHARACTER_MAXIMUM_LENGTH,
    IS_NULLABLE
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_NAME = 'users';

-- 테이블 생성
CREATE TABLE users (
    id INT IDENTITY(1,1) PRIMARY KEY,
    username NVARCHAR(50) NOT NULL,
    email NVARCHAR(100) UNIQUE,
    age INT CHECK (age >= 0),
    created_date DATETIME2 DEFAULT GETDATE(),
    is_active BIT DEFAULT 1
);

-- 테이블 수정
ALTER TABLE users ADD phone NVARCHAR(20);
ALTER TABLE users DROP COLUMN phone;
ALTER TABLE users ALTER COLUMN email NVARCHAR(200);

-- 컬럼 이름 변경
EXEC sp_rename 'users.old_column', 'new_column', 'COLUMN';

-- 테이블 이름 변경
EXEC sp_rename 'old_table', 'new_table';

-- 테이블 삭제
DROP TABLE users;

-- 테이블 자르기 (TRUNCATE)
TRUNCATE TABLE users;
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

-- 정렬 및 제한
SELECT * FROM users ORDER BY created_date DESC;
SELECT TOP 10 * FROM users;
SELECT TOP 10 PERCENT * FROM users;

-- OFFSET/FETCH (SQL Server 2012+)
SELECT * FROM users ORDER BY id OFFSET 10 ROWS FETCH NEXT 5 ROWS ONLY;

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

-- IIF 함수 (SQL Server 2012+)
SELECT username, IIF(age >= 18, 'Adult', 'Minor') as status FROM users;
```

### INSERT - 데이터 삽입

```sql
-- 단일 행 삽입
INSERT INTO users (username, email, age) VALUES ('john', 'john@email.com', 25);

-- 다중 행 삽입
INSERT INTO users (username, email, age) VALUES
    ('alice', 'alice@email.com', 30),
    ('bob', 'bob@email.com', 28);

-- IDENTITY 컬럼 값 확인
INSERT INTO users (username, email) VALUES ('charlie', 'charlie@email.com');
SELECT SCOPE_IDENTITY() as new_id;  -- 현재 세션의 마지막 IDENTITY 값

-- OUTPUT 절 (삽입된 데이터 반환)
INSERT INTO users (username, email)
OUTPUT INSERTED.id, INSERTED.username, INSERTED.created_date
VALUES ('david', 'david@email.com');

-- 서브쿼리로 삽입
INSERT INTO users (username, email)
SELECT name, email FROM temp_users WHERE active = 1;

-- SELECT INTO (새 테이블 생성과 동시에 데이터 삽입)
SELECT * INTO users_backup FROM users WHERE created_date < '2023-01-01';
```

### UPDATE - 데이터 수정

```sql
-- 기본 수정
UPDATE users SET email = 'newemail@email.com' WHERE id = 1;
UPDATE users SET age = age + 1 WHERE created_date < '2023-01-01';

-- 다중 컬럼 수정
UPDATE users SET username = 'newname', email = 'newemail@email.com' WHERE id = 1;

-- JOIN을 이용한 수정
UPDATE u
SET u.city = a.city
FROM users u
INNER JOIN addresses a ON u.id = a.user_id;

-- OUTPUT 절
UPDATE users
SET age = 30
OUTPUT DELETED.age as old_age, INSERTED.age as new_age
WHERE username = 'john';

-- TOP을 이용한 제한 수정
UPDATE TOP(10) users SET is_active = 0 WHERE last_login < '2022-01-01';
```

### DELETE - 데이터 삭제

```sql
-- 기본 삭제
DELETE FROM users WHERE id = 1;
DELETE FROM users WHERE created_date < '2022-01-01';

-- OUTPUT 절
DELETE FROM users
OUTPUT DELETED.username, DELETED.age
WHERE age < 18;

-- JOIN을 이용한 삭제
DELETE u
FROM users u
INNER JOIN inactive_list i ON u.id = i.user_id;

-- TOP을 이용한 제한 삭제
DELETE TOP(100) FROM users WHERE is_active = 0;

-- 모든 데이터 삭제
DELETE FROM users;
TRUNCATE TABLE users;  -- 빠름, IDENTITY 리셋
```

## 7. 조인 (JOIN)

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

-- CROSS JOIN
SELECT u.username, p.product_name
FROM users u
CROSS JOIN products p;

-- CROSS APPLY
SELECT u.username, recent_orders.order_date
FROM users u
CROSS APPLY (
    SELECT TOP 1 order_date
    FROM orders o
    WHERE o.user_id = u.id
    ORDER BY order_date DESC
) recent_orders;
```

## 8. 집계 함수 및 그룹화

```sql
-- 기본 집계 함수
SELECT COUNT(*) FROM users;
SELECT COUNT(DISTINCT email) FROM users;
SELECT SUM(price) FROM products;
SELECT AVG(CAST(age AS FLOAT)) FROM users;
SELECT MAX(price), MIN(price) FROM products;

-- 문자열 집계 (SQL Server 2017+)
SELECT STRING_AGG(username, ', ') FROM users;

-- GROUP BY
SELECT status, COUNT(*) FROM orders GROUP BY status;
SELECT city, AVG(CAST(age AS FLOAT)) FROM users GROUP BY city;
SELECT YEAR(created_date), COUNT(*)
FROM users
GROUP BY YEAR(created_date);

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

-- GROUPING SETS
SELECT city, status, COUNT(*)
FROM users
GROUP BY GROUPING SETS ((city), (status), ());
```

## 9. 윈도우 함수 (분석 함수)

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

## 10. CTE (Common Table Expression)

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
WITH employee_hierarchy AS (
    -- 앵커 멤버
    SELECT id, name, manager_id, 1 as level
    FROM employees
    WHERE manager_id IS NULL

    UNION ALL

    -- 재귀 멤버
    SELECT e.id, e.name, e.manager_id, eh.level + 1
    FROM employees e
    INNER JOIN employee_hierarchy eh ON e.manager_id = eh.id
)
SELECT * FROM employee_hierarchy ORDER BY level, name;

-- 다중 CTE
WITH
sales_summary AS (
    SELECT product_id, SUM(quantity) as total_sold
    FROM sales
    GROUP BY product_id
),
product_info AS (
    SELECT id, name, category
    FROM products
)
SELECT p.name, p.category, s.total_sold
FROM product_info p
LEFT JOIN sales_summary s ON p.id = s.product_id;
```

## 11. 트랜잭션 제어 (TCL)

```sql
-- 트랜잭션 시작
BEGIN TRANSACTION;
BEGIN TRAN;

-- 커밋
COMMIT TRANSACTION;
COMMIT TRAN;
COMMIT;

-- 롤백
ROLLBACK TRANSACTION;
ROLLBACK TRAN;
ROLLBACK;

-- 명명된 트랜잭션
BEGIN TRANSACTION my_transaction;
COMMIT TRANSACTION my_transaction;

-- 세이브포인트
BEGIN TRANSACTION;
SAVE TRANSACTION savepoint1;
-- some operations
ROLLBACK TRANSACTION savepoint1;
COMMIT TRANSACTION;

-- 트랜잭션 격리 수준
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;
SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
SET TRANSACTION ISOLATION LEVEL SNAPSHOT;

-- 자동 커밋 설정
SET AUTOCOMMIT ON;
SET AUTOCOMMIT OFF;
```

## 12. 사용자 및 보안 관리

```sql
-- 로그인 생성 (서버 수준)
CREATE LOGIN username WITH PASSWORD = 'password';
CREATE LOGIN username FROM WINDOWS;

-- 사용자 생성 (데이터베이스 수준)
CREATE USER username FOR LOGIN username;
CREATE USER username WITHOUT LOGIN;  -- 포함된 데이터베이스용

-- 권한 부여
GRANT SELECT ON users TO username;
GRANT INSERT, UPDATE, DELETE ON users TO username;
GRANT ALL ON SCHEMA::dbo TO username;

-- 역할 생성 및 할당
CREATE ROLE readonly_role;
GRANT SELECT ON SCHEMA::dbo TO readonly_role;
ALTER ROLE readonly_role ADD MEMBER username;

-- 기본 제공 역할
ALTER ROLE db_datareader ADD MEMBER username;
ALTER ROLE db_datawriter ADD MEMBER username;
ALTER ROLE db_owner ADD MEMBER username;

-- 권한 확인
SELECT
    p.principal_id,
    p.name as principal_name,
    p.type_desc as principal_type,
    per.permission_name,
    per.state_desc as permission_state
FROM sys.database_permissions per
LEFT JOIN sys.objects obj ON per.major_id = obj.object_id
LEFT JOIN sys.database_principals p ON per.grantee_principal_id = p.principal_id;

-- 사용자 삭제
DROP USER username;
DROP LOGIN username;
```

## 13. 인덱스 관리

```sql
-- 인덱스 생성
CREATE INDEX idx_username ON users(username);
CREATE UNIQUE INDEX idx_email ON users(email);

-- 복합 인덱스
CREATE INDEX idx_name_age ON users(username, age);

-- 포함 컬럼이 있는 인덱스
CREATE INDEX idx_username_include ON users(username) INCLUDE (email, age);

-- 필터된 인덱스
CREATE INDEX idx_active_users ON users(username) WHERE is_active = 1;

-- 컬럼스토어 인덱스
CREATE COLUMNSTORE INDEX idx_cs_sales ON sales;
CREATE CLUSTERED COLUMNSTORE INDEX idx_ccs_sales ON sales;

-- 인덱스 정보 확인
SELECT
    i.name as index_name,
    i.type_desc,
    c.name as column_name
FROM sys.indexes i
INNER JOIN sys.index_columns ic ON i.object_id = ic.object_id AND i.index_id = ic.index_id
INNER JOIN sys.columns c ON ic.object_id = c.object_id AND ic.column_id = c.column_id
WHERE i.object_id = OBJECT_ID('users');

-- 인덱스 사용 통계
SELECT
    object_name(ius.object_id) as table_name,
    i.name as index_name,
    ius.user_seeks,
    ius.user_scans,
    ius.user_lookups,
    ius.user_updates
FROM sys.dm_db_index_usage_stats ius
INNER JOIN sys.indexes i ON ius.object_id = i.object_id AND ius.index_id = i.index_id;

-- 인덱스 재구성/재구축
ALTER INDEX idx_username ON users REORGANIZE;
ALTER INDEX idx_username ON users REBUILD;
ALTER INDEX ALL ON users REBUILD;

-- 인덱스 삭제
DROP INDEX idx_username ON users;
```

## 14. 저장 프로시저 및 함수

```sql
-- 저장 프로시저 생성
CREATE PROCEDURE GetUserByAge
    @MinAge INT
AS
BEGIN
    SELECT * FROM users WHERE age >= @MinAge;
END;

-- 저장 프로시저 실행
EXEC GetUserByAge @MinAge = 18;
EXECUTE GetUserByAge 18;

-- 출력 매개변수가 있는 프로시저
CREATE PROCEDURE GetUserCount
    @MinAge INT,
    @UserCount INT OUTPUT
AS
BEGIN
    SELECT @UserCount = COUNT(*) FROM users WHERE age >= @MinAge;
END;

-- 출력 매개변수 사용
DECLARE @Count INT;
EXEC GetUserCount @MinAge = 18, @UserCount = @Count OUTPUT;
SELECT @Count as TotalUsers;

-- 스칼라 함수 생성
CREATE FUNCTION GetUserAge(@UserId INT)
RETURNS INT
AS
BEGIN
    DECLARE @Age INT;
    SELECT @Age = age FROM users WHERE id = @UserId;
    RETURN @Age;
END;

-- 함수 사용
SELECT username, dbo.GetUserAge(id) as age FROM users;

-- 테이블 값 함수
CREATE FUNCTION GetUsersByCity(@City NVARCHAR(50))
RETURNS TABLE
AS
RETURN
(
    SELECT * FROM users WHERE city = @City
);

-- 테이블 값 함수 사용
SELECT * FROM dbo.GetUsersByCity('Seoul');

-- 프로시저/함수 목록
SELECT name, type_desc FROM sys.objects
WHERE type IN ('P', 'FN', 'IF', 'TF');

-- 프로시저/함수 삭제
DROP PROCEDURE GetUserByAge;
DROP FUNCTION GetUserAge;
```

## 15. 트리거

```sql
-- INSERT 트리거
CREATE TRIGGER tr_users_insert
ON users
AFTER INSERT
AS
BEGIN
    INSERT INTO audit_log (table_name, action, user_name, timestamp)
    SELECT 'users', 'INSERT', SYSTEM_USER, GETDATE()
    FROM inserted;
END;

-- UPDATE 트리거
CREATE TRIGGER tr_users_update
ON users
AFTER UPDATE
AS
BEGIN
    INSERT INTO audit_log (table_name, action, user_name, timestamp, old_values, new_values)
    SELECT
        'users',
        'UPDATE',
        SYSTEM_USER,
        GETDATE(),
        (SELECT * FROM deleted FOR JSON AUTO),
        (SELECT * FROM inserted FOR JSON AUTO);
END;

-- INSTEAD OF 트리거 (뷰용)
CREATE TRIGGER tr_view_insert
ON v_user_summary
INSTEAD OF INSERT
AS
BEGIN
    INSERT INTO users (username, email)
    SELECT username, email FROM inserted;
END;

-- 트리거 목록
SELECT name, type_desc, is_disabled FROM sys.triggers;

-- 트리거 비활성화/활성화
DISABLE TRIGGER tr_users_insert ON users;
ENABLE TRIGGER tr_users_insert ON users;

-- 트리거 삭제
DROP TRIGGER tr_users_insert;
```

## 16. 뷰 관리

```sql
-- 뷰 생성
CREATE VIEW v_active_users AS
SELECT id, username, email
FROM users
WHERE is_active = 1;

-- 인덱싱된 뷰 (구체화된 뷰)
CREATE VIEW v_user_summary
WITH SCHEMABINDING
AS
SELECT
    city,
    COUNT_BIG(*) as user_count,
    AVG(CAST(age AS FLOAT)) as avg_age
FROM dbo.users
WHERE is_active = 1
GROUP BY city;

CREATE UNIQUE CLUSTERED INDEX idx_v_user_summary ON v_user_summary(city);

-- 뷰 수정
ALTER VIEW v_active_users AS
SELECT id, username, email, phone
FROM users
WHERE is_active = 1;

-- 뷰 정보 확인
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.VIEWS;
SELECT name FROM sys.views;

-- 뷰 정의 확인
SELECT OBJECT_DEFINITION(OBJECT_ID('v_active_users'));

-- 뷰 삭제
DROP VIEW v_active_users;
```

## 17. 임시 테이블

```sql
-- 로컬 임시 테이블 (#)
CREATE TABLE #temp_users (
    id INT,
    username NVARCHAR(50)
);

INSERT INTO #temp_users VALUES (1, 'john'), (2, 'alice');
SELECT * FROM #temp_users;
-- 세션 종료 시 자동 삭제

-- 글로벌 임시 테이블 (##)
CREATE TABLE ##global_temp (
    id INT,
    data NVARCHAR(100)
);
-- 모든 세션에서 접근 가능, 마지막 세션 종료 시 삭제

-- 테이블 변수
DECLARE @temp_table TABLE (
    id INT,
    username NVARCHAR(50)
);

INSERT INTO @temp_table VALUES (1, 'john'), (2, 'alice');
SELECT * FROM @temp_table;
```

## 18. JSON 데이터 처리 (SQL Server 2016+)

```sql
-- JSON 데이터 조회
SELECT username, JSON_VALUE(preferences, '$.theme') as theme
FROM users;

-- JSON 배열 요소 추출
SELECT username, JSON_VALUE(preferences, '$.languages[0]') as first_language
FROM users;

-- JSON 객체를 테이블로 변환
SELECT *
FROM OPENJSON('{"name": "John", "age": 30, "city": "Seoul"}')
WITH (
    name NVARCHAR(50),
    age INT,
    city NVARCHAR(50)
);

-- JSON 경로로 데이터 추출
SELECT username, value as skill
FROM users
CROSS APPLY OPENJSON(preferences, '$.skills') as skills;

-- FOR JSON으로 JSON 생성
SELECT id, username, email
FROM users
FOR JSON AUTO;

-- JSON 조건 검색
SELECT * FROM users
WHERE JSON_VALUE(preferences, '$.theme') = 'dark';

-- JSON 데이터 수정
UPDATE users
SET preferences = JSON_MODIFY(preferences, '$.theme', 'light')
WHERE id = 1;
```

## 19. 문자열 함수

```sql
-- 기본 문자열 함수
SELECT CONCAT(first_name, ' ', last_name) as full_name FROM users;
SELECT SUBSTRING(email, 1, 5) FROM users;
SELECT LEN(username) FROM users;
SELECT UPPER(username), LOWER(email) FROM users;
SELECT LTRIM(RTRIM(username)) FROM users;
SELECT REPLACE(email, '@', ' at ') FROM users;

-- 문자열 분할 (SQL Server 2016+)
SELECT value FROM STRING_SPLIT('apple,banana,orange', ',');

-- 패딩
SELECT RIGHT('00000' + CAST(id AS NVARCHAR), 5) as padded_id FROM users;

-- 문자열 검색
SELECT * FROM users WHERE CHARINDEX('@gmail.com', email) > 0;
SELECT * FROM users WHERE email LIKE '%@gmail.com';

-- 문자열 집계 (SQL Server 2017+)
SELECT STRING_AGG(username, ', ') WITHIN GROUP (ORDER BY username) FROM users;

-- FORMAT 함수
SELECT FORMAT(GETDATE(), 'yyyy-MM-dd') as formatted_date;
SELECT FORMAT(1234.56, 'C', 'ko-KR') as currency;  -- ₩1,235
```

## 20. 날짜/시간 함수

```sql
-- 현재 날짜/시간
SELECT GETDATE();          -- 현재 날짜시간
SELECT GETUTCDATE();       -- UTC 날짜시간
SELECT SYSDATETIME();      -- 더 정확한 현재 시간
SELECT CURRENT_TIMESTAMP;  -- 표준 SQL

-- 날짜 연산
SELECT DATEADD(day, 1, GETDATE());     -- 1일 후
SELECT DATEADD(month, -3, GETDATE());  -- 3개월 전
SELECT DATEDIFF(day, '2023-01-01', GETDATE());  -- 날짜 차이

-- 날짜 부분 추출
SELECT YEAR(created_date), MONTH(created_date), DAY(created_date) FROM users;
SELECT DATEPART(hour, created_date) FROM users;
SELECT DATENAME(month, created_date) FROM users;  -- 월 이름

-- 날짜 포맷
SELECT FORMAT(GETDATE(), 'yyyy-MM-dd HH:mm:ss');
SELECT CONVERT(VARCHAR, GETDATE(), 120);  -- YYYY-MM-DD HH:MM:SS

-- 날짜 절단
SELECT CAST(GETDATE() AS DATE);  -- 시간 부분 제거
SELECT DATETRUNC(month, GETDATE());  -- 월 첫날 (SQL Server 2022+)

-- 날짜 유효성 검사
SELECT ISDATE('2023-02-29');  -- 0 (invalid)
SELECT ISDATE('2024-02-29');  -- 1 (valid)
```

## 21. 시스템 정보 및 모니터링

```sql
-- 서버 정보
SELECT @@VERSION;
SELECT @@SERVERNAME;
SELECT SERVERPROPERTY('ProductVersion');
SELECT SERVERPROPERTY('Edition');

-- 데이터베이스 정보
SELECT name, database_id, create_date FROM sys.databases;
SELECT DB_NAME(), DB_ID();

-- 현재 연결 정보
SELECT
    session_id,
    login_name,
    host_name,
    program_name,
    last_request_start_time
FROM sys.dm_exec_sessions
WHERE is_user_process = 1;

-- 실행 중인 쿼리
SELECT
    s.session_id,
    r.status,
    r.command,
    t.text as sql_text,
    r.percent_complete
FROM sys.dm_exec_requests r
INNER JOIN sys.dm_exec_sessions s ON r.session_id = s.session_id
CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) t;

-- 대기 통계
SELECT
    wait_type,
    waiting_tasks_count,
    wait_time_ms,
    signal_wait_time_ms
FROM sys.dm_os_wait_stats
ORDER BY wait_time_ms DESC;

-- 데이터베이스 크기
SELECT
    name,
    size * 8.0 / 1024 as size_mb,
    max_size * 8.0 / 1024 as max_size_mb
FROM sys.database_files;

-- 테이블 크기
SELECT
    t.name as table_name,
    SUM(a.total_pages) * 8 as total_kb,
    SUM(a.used_pages) * 8 as used_kb
FROM sys.tables t
INNER JOIN sys.indexes i ON t.object_id = i.object_id
INNER JOIN sys.partitions p ON i.object_id = p.object_id AND i.index_id = p.index_id
INNER JOIN sys.allocation_units a ON p.partition_id = a.container_id
WHERE t.is_ms_shipped = 0
GROUP BY t.name;

-- 잠금 정보
SELECT
    request_session_id,
    resource_type,
    resource_database_id,
    resource_description,
    request_mode,
    request_status
FROM sys.dm_tran_locks;
```

## 22. 백업 및 복구

```sql
-- 전체 백업
BACKUP DATABASE MyDatabase
TO DISK = 'C:\Backup\MyDatabase.bak'
WITH FORMAT, COMPRESSION;

-- 차등 백업
BACKUP DATABASE MyDatabase
TO DISK = 'C:\Backup\MyDatabase_diff.bak'
WITH DIFFERENTIAL, COMPRESSION;

-- 트랜잭션 로그 백업
BACKUP LOG MyDatabase
TO DISK = 'C:\Backup\MyDatabase_log.trn';

-- 백업 정보 확인
SELECT
    database_name,
    backup_start_date,
    backup_finish_date,
    type,
    backup_size / 1024 / 1024 as backup_size_mb
FROM msdb.dbo.backupset
ORDER BY backup_start_date DESC;

-- 복원
RESTORE DATABASE MyDatabase
FROM DISK = 'C:\Backup\MyDatabase.bak'
WITH REPLACE;

-- 차등 복원
RESTORE DATABASE MyDatabase
FROM DISK = 'C:\Backup\MyDatabase.bak'
WITH NORECOVERY;

RESTORE DATABASE MyDatabase
FROM DISK = 'C:\Backup\MyDatabase_diff.bak'
WITH RECOVERY;

-- 특정 시점 복원
RESTORE DATABASE MyDatabase
FROM DISK = 'C:\Backup\MyDatabase.bak'
WITH NORECOVERY;

RESTORE LOG MyDatabase
FROM DISK = 'C:\Backup\MyDatabase_log.trn'
WITH STOPAT = '2023-12-25 14:30:00';
```

## 23. 성능 최적화

```sql
-- 실행 계획
SET SHOWPLAN_ALL ON;
SELECT * FROM users WHERE age > 25;
SET SHOWPLAN_ALL OFF;

-- 실제 실행 계획 (Management Studio에서)
SET STATISTICS IO ON;
SET STATISTICS TIME ON;
SELECT * FROM users WHERE age > 25;

-- 인덱스 조각화 확인
SELECT
    object_name(ips.object_id) as table_name,
    i.name as index_name,
    ips.avg_fragmentation_in_percent,
    ips.page_count
FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, 'DETAILED') ips
INNER JOIN sys.indexes i ON ips.object_id = i.object_id AND ips.index_id = i.index_id
WHERE ips.avg_fragmentation_in_percent > 10;

-- 통계 업데이트
UPDATE STATISTICS users;
UPDATE STATISTICS users idx_username WITH FULLSCAN;

-- 쿼리 힌트
SELECT * FROM users WITH (INDEX(idx_username)) WHERE username = 'john';
SELECT * FROM users WITH (NOLOCK) WHERE age > 25;  -- 더티 읽기 허용

-- 플랜 가이드 생성
EXEC sp_create_plan_guide
    @name = 'guide1',
    @stmt = 'SELECT * FROM users WHERE age > @age',
    @type = 'TEMPLATE',
    @module_or_batch = NULL,
    @params = '@age int',
    @hints = 'OPTION (FORCE ORDER)';
```

## 24. 파티셔닝

```sql
-- 파티션 함수 생성
CREATE PARTITION FUNCTION pf_sales_date (DATE)
AS RANGE RIGHT FOR VALUES
('2023-01-01', '2023-04-01', '2023-07-01', '2023-10-01');

-- 파티션 스키마 생성
CREATE PARTITION SCHEME ps_sales_date
AS PARTITION pf_sales_date
TO ([PRIMARY], [PRIMARY], [PRIMARY], [PRIMARY], [PRIMARY]);

-- 파티션된 테이블 생성
CREATE TABLE sales (
    id INT IDENTITY(1,1),
    sale_date DATE,
    amount DECIMAL(10,2)
) ON ps_sales_date(sale_date);

-- 파티션 정보 확인
SELECT
    t.name as table_name,
    p.partition_number,
    p.rows,
    rv.value as boundary_value
FROM sys.tables t
INNER JOIN sys.partitions p ON t.object_id = p.object_id
INNER JOIN sys.partition_schemes ps ON p.partition_id = ps.data_space_id
INNER JOIN sys.partition_functions pf ON ps.function_id = pf.function_id
LEFT JOIN sys.partition_range_values rv ON pf.function_id = rv.function_id
    AND p.partition_number = rv.boundary_id + 1
WHERE t.name = 'sales';

-- 파티션 스위치 (빠른 데이터 이동)
ALTER TABLE sales SWITCH PARTITION 1 TO sales_archive PARTITION 1;
```
