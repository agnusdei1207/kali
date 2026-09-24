# PostgreSQL CLI 실전 탐색 명령어 치트시트

# 1. DB 접속

sudo docker exec -it postgresql psql -U postgres
psql -h localhost -U postgres -d [DB명] # 직접 접속

# 2. 데이터베이스 목록 확인

\l # 모든 DB 리스트
\c [DB명] # 해당 DB로 접속 (필수: DB명)

# 3. 스키마/테이블/컬럼 탐색

\dn # 스키마 목록
\dt # 테이블 목록
\dt [스키마명].\* # 특정 스키마 내 테이블 목록
\d [테이블명] # 테이블 구조(컬럼, 타입 등)
\d+ [테이블명] # 테이블 상세 정보

# 4. 유저/권한 확인

\du # DB 유저 목록
\dg # 그룹 목록

# 5. 쿼리/데이터 확인

SELECT \* FROM [테이블명] LIMIT 10; # 데이터 일부 조회
SELECT column_name FROM information_schema.columns WHERE table_name='[테이블명]'; # 컬럼명 확인

# 6. 탐색/이동/나가기

\q # psql 종료
\? # 명령어 전체 도움말
\! [명령어] # 쉘 명령 실행 (ex: \! ls)
\conninfo # 현재 접속 정보 확인

# 7. 기타

\df # 함수 목록
\ds # 시퀀스 목록
\dv # 뷰 목록

# 옵션/파라미터

# -U [필수] : DB 유저명

# -h [선택] : 호스트

# -d [선택] : DB명

# [테이블명], [스키마명] 등은 직접 탐색하며 확인

# 실전 활용

# DB 구조, 유저, 권한, 데이터, 플래그, 설정 등 빠르게 탐색
