nmap -p <포트> -Pn -n --open -sV --script="mysql\*" <아이피>
mysql -u <유저> -p -h <아이피/호스트이름> -P <포트>
mysql -u root -p -h 172.31.1.1 -P 33060

# 데이터베이스 확인
show databases;

# 데이터베이스 사용
use <데이터베이스>;

# 테이블 확인
show tables;

# 테이블 내 모든 열 & 행 확인
select \* from <테이블>;

# 특정 열(column) 내 특정 문자열 확인
select \* from <테이블> where lower(<열>) like '%<문자열>%';

# 예) 유저 이름 열 중 Garcia가 포함된 행의 username, password 반환
MySQL [production]> select username,password from users where lower(username) like '%garcia%';
+-------------+------------+
| username | password |
+-------------+------------+
| garcia.liam | LiamG#2023 |
+-------------+------------+

# 특정 데이터베이스 내 특정 테이블 덤프

mysqldump -h <아이피/dns> -u <유저> -p -P <포트> <DB이름> <테이블이름> > <파일이름>
mysqldump -h 172.31.198.21 -u root -p -P 33060 production users > usertabledump.sql

# 특정 데이터베이스 전체 덤프

mysqldump -h <아이피/dns> -u <유저> -p -P <포트> <DB이름> > <파일이름>
mysqldump -h 172.31.198.21 -u root -p -P 33060 production > productiondbdump.sql

# 예

┌──(root㉿kali)-[~/groot]  
└─# mysqldump -h 172.31.198.21 -u root -p -P 33060 production users > usertabledump.sql
Enter password:

┌──(root㉿kali)-[~/groot]  
└─# cat usertabledump.sql
