# Bruteforce 치트시트

- 이 폴더 — 대상 서비스에 로그인 시도를 반복하는 온라인 브루트포스와, 그에 쓸 커스텀 단어사전 생성을 다룬다.
- 로그인 폼·네트워크 서비스에 자격증명을 시도해야 하는데 워드리스트가 없을 때 cewl로 생성하고, IP 차단·프록시 조건이 붙으면 use-proxy·x-forwarded-for 문서를 쓴다.
- 획득한 해시·암호화 파일을 로컬에서 깨는 오프라인 크래킹은 `cracking/` 폴더가 담당한다.

## 폴더 구성

- `cewl/cewl.md` — cewl로 대상 사이트를 크롤링해 커스텀 단어사전 생성
- `use-proxy/` — 프록시를 경유해 로그인 시도를 반복하는 자동화 스크립트
  - `use-proxy/generate_port.sh`, `use-proxy/scan_generated_ports.sh`
  - `use-proxy/proxy_bruteforce.py`
- `x-forwarded-for/` — X-Forwarded-For 헤더 조합으로 IP 차단을 우회하는 브루트포스
  - `x-forwarded-for/bruteforce_x_forwarded_for.py`
  - `x-forwarded-for/proxy_bruteforce_x_forwarded_for.py`

## cracking 폴더와의 역할 구분

- bruteforce는 대상에 실제 로그인 시도를 반복하는 온라인 공격, cracking은 해시를 로컬에서 깨는 오프라인 크래킹이다.
- `cracking/john/` — John the Ripper(unshadow, ssh 키, 커스텀 룰)
- `cracking/hashcat/` — hashcat 모드·공격 방식·GPU 설정
- `cracking/rockyou.md`, `cracking/wordlists.md`, `cracking/seclists.md` — 워드리스트 소스

## hydra는 cracking 폴더에 있다

- hydra 같은 네트워크 로그인 브루트포스 도구 문서는 `cracking/hydra/`에 있다.
- `cracking/hydra/hydra.md` — 기본 사용법
- `cracking/hydra/hydra-structured.md` — 프로토콜별 정리
- `cracking/hydra/hydra_practice.md` — 실습 기록

## 표준 흐름

```bash
# 1. cewl로 대상 특화 단어사전 생성
cewl -d 3 -m 6 -w corp_words.txt http://10.10.10.10

# 2. 생성한 사전을 hydra 로그인 브루트포스에 투입
hydra -l admin -P corp_words.txt 10.10.10.10 http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"

# 3. 해시를 얻었으면 cracking 폴더로
john --wordlist=corp_words.txt hash.txt
```

- 단어사전 생성(cewl) -> 온라인 시도(hydra) -> 해시 획득 -> 오프라인 크래킹(john/hashcat) 순서로 문서가 이어진다.

## 관련 문서

- `cracking/README.md` — 크래킹 폴더 인덱스
- `recon/` — 대상 서비스·버전·계정 정보 수집
