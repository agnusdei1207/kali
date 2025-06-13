# 🔍 DNS 열거(Enumeration) 기법

DNS(Domain Name System) 열거는 대상 도메인 또는 네트워크에 관한 중요 정보를 수집하는 프로세스입니다. OSCP 시험에서 DNS 열거는 추가적인 공격 벡터를 찾고 내부 네트워크 구조를 파악하는 데 필수적입니다.

## 0. DNS 툴 설치 방법

### 🔹 주요 DNS 도구 설치

```bash
# 기본 DNS 도구 설치 (host, dig, nslookup 등)
sudo apt update
sudo apt install -y dnsutils bind9-utils

# whois 정보 조회 도구 설치
sudo apt install -y whois

# 고급 DNS 분석을 위한 도구 설치
sudo apt install -y dnsenum dnsmap
```

### 🔹 설치 확인 방법

```bash
# 성공적으로 설치되었는지 확인
which host
which dig
which nslookup
```

### 🔹 도구별 기능 설명

1. **dnsutils**: `host`, `dig`, `nslookup`과 같은 기본 DNS 쿼리 도구를 포함
2. **bind9-utils**: `delv`, `nsupdate` 등 DNS 서버 관련 고급 도구 포함
3. **whois**: 도메인 등록 정보 조회 도구
4. **dnsenum**: DNS 정보 자동화 수집 도구 (OSCP에선 제한적으로 사용)
5. **dnsmap**: DNS 맵핑 도구 (보조용으로 활용)

## 1. 기본 DNS 정보 수집

### 🔹 도메인 이름 확인

```bash
# nslookup을 사용한 기본 IP 해석
nslookup example.com

# 역방향 DNS 조회
nslookup 10.10.10.10

# 대화형 모드에서 다양한 레코드 조회
nslookup
> set type=A
> example.com
> set type=MX
> example.com
> exit
```

### 🔹 호스트 정보 수집

```bash
# host 명령어를 사용한 DNS 조회
host example.com

# IP 주소에 대한 역방향 조회
host 10.10.10.10

# 모든 정보 조회
host -a example.com
```

### 🔹 기본 DNS 레코드 조회

```bash
# A 레코드 조회 (IPv4)
host -t A example.com

# AAAA 레코드 조회 (IPv6)
host -t AAAA example.com

# MX 레코드 조회 (메일 서버)
host -t MX example.com

# NS 레코드 조회 (네임서버)
host -t NS example.com

# TXT 레코드 조회 (텍스트 정보)
host -t TXT example.com

# SOA 레코드 조회 (권한 정보)
host -t SOA example.com

# CNAME 레코드 조회 (별칭)
host -t CNAME www.example.com

# PTR 레코드 조회 (역방향 DNS)
host -t PTR 10.10.10.10.in-addr.arpa
```

### 🔹 WHOIS 정보 조회

```bash
# 도메인 등록 정보 조회
whois example.com

# IP 주소 소유권 정보 조회
whois 10.10.10.10
```

## 2. dig를 사용한 고급 DNS 정보 수집

### 🔹 기본 dig 사용법

```bash
# 기본 도메인 정보 조회
dig example.com

# 특정 레코드 타입 조회
dig example.com A
dig example.com MX
dig example.com NS

# 간략한 출력
dig example.com +short

# 추적 정보 포함 (경로 추적)
dig example.com +trace

# 모든 DNS 레코드 조회
dig example.com ANY
```

### 🔹 특정 DNS 서버 질의

```bash
# 특정 DNS 서버에 질의
dig @8.8.8.8 example.com

# 특정 네임서버에 질의
dig @ns1.example.com example.com

# 특정 DNS 서버에 대한 버전 정보 요청
dig @ns1.example.com version.bind CHAOS TXT

# TCP 모드로 질의 (UDP 차단 우회)
dig @ns1.example.com example.com +tcp
```

### 🔹 DNS 트랜스퍼 시도 (Zone Transfer)

```bash
# Zone Transfer 시도 (dig)
dig @ns1.example.com example.com AXFR

# Zone Transfer 시도 (host)
host -l example.com ns1.example.com

# 특정 존에 대한 영역 전송
dig @ns1.example.com subdomain.example.com AXFR
```

## 3. DNS 브루트포싱 (수동 접근)

### 🔹 서브도메인 발견 방법

```bash
# 일반적인 서브도메인 수동 확인
for sub in www mail remote blog webmail server ns1 ns2 ns3 ns4 cpanel ftp; do
    host $sub.example.com | grep "has address" && echo "$sub.example.com 발견!"
done

# 워드리스트를 활용한 조금 더 확장된 방법
for sub in $(cat /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1000.txt); do
    host $sub.example.com | grep "has address" && echo "$sub.example.com 발견!"
done

# 다중 도메인에 대한 브루트포싱
for domain in example.com example.org; do
    for sub in www mail admin; do
        host $sub.$domain | grep "has address" && echo "$sub.$domain 발견!"
    done
done
```

### 🔹 서브도메인에 대한 역방향 조회

```bash
# IP 범위 내에서 PTR 레코드 확인
for ip in $(seq 1 254); do
    host 10.10.10.$ip | grep "domain name pointer" && echo "10.10.10.$ip 발견!"
done

# 다중 C 클래스에 대한 PTR 레코드 확인
for subnet in 10 11 12; do
    for ip in $(seq 1 254); do
        host 10.10.$subnet.$ip | grep "domain name pointer" && echo "10.10.$subnet.$ip 발견!"
    done
done
```

### 🔹 와일드카드 DNS 탐지

```bash
# 와일드카드 DNS 설정 확인
host random123456.example.com

# 여러 무작위 호스트명 테스트
for i in {1..5}; do
    random=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10 | head -n 1)
    host $random.example.com
done
```

## 4. DNS 캐시 스누핑 및 고급 기법

### 🔹 캐시 스누핑 기본

```bash
# 비재귀적 쿼리로 캐시 정보 확인
dig @target-dns.example.com +norecurse example.com

# 특정 레코드 캐시 확인
dig @target-dns.example.com +norecurse mail.example.com MX

# 여러 일반적인 도메인에 대한 캐시 확인
for domain in google.com facebook.com twitter.com; do
    dig @target-dns.example.com +norecurse $domain A | grep -A2 "ANSWER SECTION"
done
```

### 🔹 DNS 서버 정보 노출 확인

```bash
# DNS 서버 버전 정보 요청
dig @ns1.example.com version.bind CHAOS TXT

# DNS 서버 호스트명 요청
dig @ns1.example.com hostname.bind CHAOS TXT

# DNS 서버 ID 요청
dig @ns1.example.com id.server CHAOS TXT
```

### 🔹 DNS 서버 설정 취약점 확인

```bash
# 재귀적 쿼리 허용 여부 확인 (DNS 증폭 공격 가능성)
dig @ns1.example.com google.com

# DNS 요청 속도 제한 테스트 (DoS 방지 설정 확인)
for i in {1..20}; do
    dig @ns1.example.com random$i.example.com +tries=1 +time=1
done
```

## 5. DNS 정보 기반 네트워크 매핑

### 🔹 발견된 호스트 목록 생성

```bash
# 발견된 모든 호스트를 파일로 저장
for sub in www mail blog admin vpn remote support dev stage; do
    host $sub.example.com | grep "has address" >> hosts.txt
done

# 파일에서 IP 주소만 추출
cat hosts.txt | grep "has address" | awk '{print $4}' > ips.txt
```

### 🔹 네트워크 범위 추정

```bash
# 발견된 IP 주소 분석
cat ips.txt | awk -F. '{print $1"."$2"."$3}' | sort -u

# CIDR 표기법으로 네트워크 범위 추정
cat ips.txt | cut -d. -f1-3 | sort -u | while read subnet; do
    echo "$subnet.0/24"
done
```

### 🔹 DNS 정보를 활용한 조직 구조 추정

```bash
# MX 레코드 분석으로 이메일 인프라 파악
dig example.com MX +short

# 각 MX 레코드의 A 레코드 확인
for mx in $(dig example.com MX +short | awk '{print $2}'); do
    dig $mx A +short
done

# SPF 레코드 분석을 통한 인가된 메일 서버 확인
dig example.com TXT +short | grep "v=spf"
```

## 6. 실제 시나리오 예시

### 🔹 시나리오 1: DNS 영역 전송 취약점

1. NS 레코드 확인:

```bash
host -t NS example.com
# 결과: example.com name server ns1.example.com.
# 결과: example.com name server ns2.example.com.
```

2. 영역 전송(Zone Transfer) 시도:

```bash
dig @ns1.example.com example.com AXFR
# 결과:
# ; <<>> DiG 9.16.1 <<>> @ns1.example.com example.com AXFR
# ...
# example.com.        3600    IN      SOA     ns1.example.com. admin.example.com. ...
# example.com.        3600    IN      NS      ns1.example.com.
# example.com.        3600    IN      NS      ns2.example.com.
# example.com.        3600    IN      A       10.10.10.10
# admin.example.com.  3600    IN      A       10.10.10.11
# db.example.com.     3600    IN      A       10.10.10.12
# dev.example.com.    3600    IN      A       10.10.10.13
# internal.example.com. 3600  IN      A       10.10.10.14
# ...
```

3. 발견된 호스트 정보 활용:

```bash
# 새로운 대상에 대한 Nmap 스캔
nmap -sS -A -p- admin.example.com db.example.com

# 발견된 모든 서브도메인에 대한 웹 서비스 확인
for sub in admin db dev internal; do
    curl -I http://$sub.example.com/ -m 3
done
```

### 🔹 시나리오 2: DNS 캐시 독소화(Cache Poisoning) 확인

1. 비재귀적 쿼리 요청:

```bash
dig @dns.target.com +norecurse example.com
```

2. 응답 TTL(Time To Live) 값 분석:

```bash
# TTL 값이 최대값에 가깝지 않다면 이미 캐싱된 응답임을 의미
dig @dns.target.com example.com | grep "^example.com" | awk '{print $2}'
```

3. 서버 재구성 없이 TTL 변경 확인:

```bash
# 첫 번째 요청에서의 TTL 저장
ttl1=$(dig @dns.target.com example.com | grep "^example.com" | awk '{print $2}')
sleep 60
# 1분 후 TTL 확인
ttl2=$(dig @dns.target.com example.com | grep "^example.com" | awk '{print $2}')
# TTL이 정확히 1분(60초) 감소했는지 확인
echo "첫 번째 TTL: $ttl1, 두 번째 TTL: $ttl2"
```

### 🔹 시나리오 3: 내부망 정보 노출 취약점 활용

1. 내부망 IP 노출 확인:

```bash
# 내부 IP 주소가 외부에 노출되었는지 확인
dig example.com ANY | grep -E '(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)'
```

2. SPF 레코드를 통한 내부 메일 서버 식별:

```bash
# SPF 레코드에서 내부 IP 범위 확인
dig example.com TXT +short | grep "v=spf" | grep -E '(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)'
```

3. DMARC 및 DKIM 레코드 확인:

```bash
# DMARC 정책 확인
dig _dmarc.example.com TXT +short

# DKIM 키 확인 (selector 필요)
dig default._domainkey.example.com TXT +short
```

## 7. DNS 열거 결과 활용법

1. **서브도메인 발견**

   - 웹 애플리케이션의 추가 엔트리 포인트 확인
   - 테스트되지 않은 서비스 또는 개발 환경 발견
   - 서브도메인 인계(Subdomain Takeover) 취약점 확인

2. **내부 네트워크 구조 파악**

   - 내부 호스트명 및 IP 주소 체계 이해
   - 네트워크 분할 전략 파악
   - 내부망과 외부망 연결 지점 식별

3. **이메일 서버 정보 수집**

   - 이메일 스피어 피싱 또는 소셜 엔지니어링 준비
   - 추가 공격 벡터 발견
   - 이메일 보안 정책 평가 (SPF, DKIM, DMARC)

4. **정보 수집 확장**

   - 발견된 모든 서브도메인에 대해 추가 열거 수행
   - 각 호스트에 대한 포트 스캔 및 서비스 식별
   - 클라우드 서비스 및 CDN 식별

5. **DNS 정보 시각화**
   ```bash
   # 간단한 도메인-IP 매핑 구성
   for sub in $(cat discovered_subdomains.txt); do
       ip=$(dig $sub +short | head -n1)
       echo "$sub -> $ip" >> dns_mapping.txt
   done
   ```

## 8. DNS 정보 수집 체크리스트

- [ ] 기본 도메인 IP 주소 조회 (A, AAAA 레코드)
- [ ] 네임서버 확인 (NS 레코드)
- [ ] 메일 서버 확인 (MX 레코드)
- [ ] 텍스트 정보 확인 (TXT 레코드)
- [ ] SPF, DKIM, DMARC 레코드 확인
- [ ] 영역 전송(Zone Transfer) 시도
- [ ] 일반적인 서브도메인 수동 확인
- [ ] 와일드카드 DNS 확인
- [ ] DNSSEC 구현 여부 확인
- [ ] 발견된 모든 도메인에 대한 추가 레코드 조회
- [ ] 역방향 DNS 조회 시도
- [ ] 네트워크 범위 추정
- [ ] DNS 서버 버전 정보 확인 시도

## 9. DNS 열거 시 주의사항

1. **소음 발생 최소화**

   - 단기간에 너무 많은 DNS 요청을 보내면 감지될 수 있음
   - 요청 속도 제한 고려
   - 중요 요청은 분산해서 실행

2. **결과 해석 주의**

   - 공개 DNS 서버는 캐시된 응답을 반환할 수 있음
   - 반드시 권한 있는 DNS 서버에 직접 질의할 것
   - CDN이나 로드 밸런서가 실제 인프라를 숨길 수 있음

3. **확인된 정보 문서화**

   - 모든 발견 사항을 체계적으로 기록
   - 추가 공격 벡터를 위한 기반으로 활용
   - 데이터 시각화로 관계 파악

4. **필터링 우회 기법 활용**
   - TCP를 통한 DNS 쿼리 고려 (UDP 필터링 우회)
   - 다양한 쿼리 유형 시도
   - 다양한 공개 DNS 서버 활용

## 10. DNS 관련 취약점 점검

### 🔹 일반적인 DNS 취약점

1. **영역 전송 허용**:

   ```bash
   # 모든 네임서버에 대해 존 전송 시도
   for ns in $(dig example.com NS +short); do
       dig @$ns example.com AXFR
   done
   ```

2. **DNS 증폭 가능성**:

   ```bash
   # 재귀적 쿼리 허용 여부 확인
   dig @ns1.example.com google.com
   ```

3. **DNSSEC 설정 확인**:

   ```bash
   # DNSSEC 구현 여부 확인
   dig example.com DNSKEY +dnssec
   dig example.com DS +dnssec
   ```

4. **DNS 캐시 스누핑**:
   ```bash
   # 자주 방문하는 도메인의 캐시 상태 확인
   dig @dns.target.com +norecurse google.com
   ```

### 🔹 OSCP 관련 DNS 취약점 점검 절차

1. **도메인 정보 수집**:

   - WHOIS 정보 조회
   - 네임서버 식별
   - SOA 레코드 확인 (관리자 이메일 등)

2. **서브도메인 열거**:

   - 일반 서브도메인 시도
   - 와일드카드 DNS 확인
   - PTR 레코드 조회

3. **DNS 서버 설정 점검**:

   - 영역 전송 허용 여부
   - 재귀 쿼리 허용 여부
   - DNS 서버 버전 정보 노출

4. **추가 정보 수집**:
   - MX, TXT 등 추가 레코드
   - SPF, DKIM, DMARC 설정
   - DNSSEC 구현 상태

---
