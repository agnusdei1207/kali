# cewl

## 개요

웹사이트를 크롤링해 사이트에 실제로 등장하는 단어로 커스텀 워드리스트를 만드는 도구다. 블로그·회사 사이트의 고유 단어(팀명, 슬로건, 제품명)가 패스워드 후보가 되는 경우가 많아 로그인 브루트포스 전에 사용한다.

## 설치

```bash
# Kali Linux (대부분 기본 설치되어 있음)
sudo apt install -y cewl

# 설치 확인
cewl --help

# 직접 설치(최신 버전) 시: Ruby 의존성 필요
sudo apt install -y ruby ruby-dev libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev
git clone https://github.com/digininja/CeWL.git
cd CeWL && bundle install
./cewl.rb
```

## 옵션 기본값과 최대치

- `-d` (크롤링 깊이): 기본 2. 상한은 없다(숫자만 만큼 링크를 따라감). 단, 깊이 1이 늘어날 때마다 요청 수가 기하급수적으로 늘어나 매우 느려지고 트래픽이 커진다. 실전에서는 2~3이면 충분하다.
- `-m` (최소 단어 길이): 기본 3. 패스워드 사전 용도면 5 이상이 노이즈가 적다. 상한은 없다.
- `-x` (최대 단어 길이): 기본 미지정(제한 없음). 긴 문장이 한 단어로 잡히는 걸 자르고 싶을 때 지정한다.
- `-w` (출력 파일): 미지정 시 결과를 화면에만 출력한다. 반드시 지정한다.

```bash
cewl --help   # 설치된 버전의 전체 옵션 확인
```

## 기본 사용

```bash
# 가장 기본: 지정 URL만 크롤링(깊이 2)해 words.txt로 저장
cewl http://<TARGET_HOST>/ -w words.txt

# 깊이 2, 5글자 이상 단어만 (패스워드 사전 용도의 표준형)
cewl http://<TARGET_HOST>/ -d 2 -m 5 -w words.txt

# 결과 확인
wc -l words.txt
cat words.txt
```

## 주요 옵션

```bash
-d 3              # 크롤링 깊이. 링크를 3단계까지 따라간다 (기본 2)
-m 5              # 최소 단어 길이 5. 짧은 단어 제외 (기본 3)
-x 15             # 최대 단어 길이 15. 긴 텍스트 제외 (기본 제한 없음)
-w words.txt      # 저장 파일
-e                # 이메일 주도 수집 (별도 파일 옵션: --email_file emails.txt)
-a                # 이미지·파일 메타데이터에서 단어 수집
--with-numbers    # 숫자가 포함된 단어도 수집 (예: team2024)
--lowercase       # 전부 소문자로 변환해 저장
-c                # 단어별 출현 횟수를 함께 출력
-g 3              # 3단어 조합도 함께 수집 (구절형 패스워드 대응)
-u "Mozilla/5.0"  # User-Agent 지정
-H "Referer: http://<TARGET_HOST>/"  # 추가 헤더
--auth_type basic --auth_user user --auth_pass pass  # 인증 필요한 사이트
--proxy_host 127.0.0.1 --proxy_port 8080             # 프록시 경유(Burp)
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

## 결과가 적을 때

- `-d 3`으로 깊이를 올린다. (링크를 더 깊게 따라가 단어를 더 모은다. 대신 시간과 요청 수가 많이 늘어난다)
- `-m`을 4로 내리고 `--with-numbers`를 붙여 후보를 늘린다.
- `-e`, `-a`로 이메일·메타데이터 단어를 추가 수집한다.
- rockyou 등 범용 리스트와 합쳐 중복 제거 후 사용한다.
