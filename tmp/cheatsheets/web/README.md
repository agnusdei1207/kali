# 웹 취약점

웹 애플리케이션 취약점 점검 내용입니다.

## SQL 인젝션

```bash
sqlmap -u "http://target/search" --dbs
```

## XSS

```bash
ffuf -u "http://target/page?search=FUZZ" -w wordlist.txt
```

## 파일 업로드

```bash
curl -F "file=@shell.php" http://target/upload
```

## 파일 포함

```php
<?php include($_GET['page']); ?>
```

## SSRF

```bash
http://target?url=http://internal-host
```

## IDOR

```bash
http://target/profile?id=1
http://target/profile?id=2
```
