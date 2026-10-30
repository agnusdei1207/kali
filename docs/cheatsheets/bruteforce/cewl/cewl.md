# cewl

## 개요

웹사이트를 크롤링해 사이트에 실제로 등장하는 단어로 커스텀 워드리스트를 만드는 도구다. 블로그·회사 사이트의 고유 단어(팀명, 슬로건, 제품명)가 패스워드 후보가 되는 경우가 많아 로그인 브루트포스 전에 사용한다.

## 기본 사용

```bash
# 웹사이트 크롤링해 워드리스트 생성 (가장 기본)
cewl http://<TARGET_HOST>/ -w words.txt

# 크롤링 깊이 2단계, 5글자 이상 단어만
cewl http://<TARGET_HOST>/ -d 2 -m 5 -w words.txt

# 결과 확인
wc -l words.txt
cat words.txt
```

## 주요 옵션

```bash
-d 2            # 크롤링 깊이 (링크 2단계까지 따라감)
-m 5            # 최소 글자 수 (기본 3, 패스워드용이면 5 이상 권장)
-w words.txt    # 저장 파일
-e              # 이메일 주소도 수집
--with-numbers  # 숫자 포함 단어 수집
-c              # 단어 출현 횟수 카운트 포함
--auth user:pass  # 인증 필요한 페이지 크롤링
```

## 실전 흐름

```bash
# 1) 대상 사이트에서 워드리스트 생성
cewl http://monster.pg/blog/ -d 2 -m 5 -w words.txt

# 2) 로그인 폼 브루트포스에 투입
hydra -l <USER> -P words.txt monster.pg http-post-form "/blog/users/login:user=^USER^&pass=^PASS^:F=failed"

# 3) 해시 크래킹 사전으로도 사용
hashcat -m 0 hashes.txt words.txt
```

## 판단 포인트

- 워드리스트가 작으면 `-d`를 늘려 더 깊이 크롤링한다.
- 등록/로그인 폼이 있으면 사용자명 목록도 같은 사이트에서 수집하면 세트로 쓴다.
- 범용 리스트(rockyou)와 합쳐 중복 제거 후 사용하면 커버리지가 늘어난다.
