# DNS 열거 기법

## 기본 명령어

```bash
# 설치 방법
apt install dnsutils whois bind9-utils -y

# 기본 도구
host target.com               # 간단한 DNS 조회
host -t A target.com          # A 레코드 조회 (IPv4)
host -t MX target.com         # MX 레코드 조회 (메일 서버)
host -t NS target.com         # NS 레코드 조회 (네임서버)
host -t TXT target.com        # TXT 레코드 조회 (텍스트 정보)
host -a target.com            # 모든 DNS 레코드 조회

# 역방향 DNS 조회
host 10.10.10.10              # IP -> 호스트명
```

## dig 고급 조회

```bash
# 기본 조회
dig target.com                # 상세 조회 결과
dig target.com +short         # 짧은 결과만 표시
dig target.com +noall +answer # 응답 섹션만 표시

# 레코드 타입 지정
dig target.com A              # A 레코드
dig target.com MX             # MX 레코드
dig target.com NS             # NS 레코드
dig target.com ANY            # 모든 레코드

# 특정 DNS 서버 지정
dig @8.8.8.8 target.com       # Google DNS 서버 사용
dig @ns1.target.com target.com # 특정 네임서버 사용

# 추가 옵션
dig target.com +trace         # 전체 DNS 트리 추적
dig -x 10.10.10.10            # 역방향 조회(PTR)
```

## nslookup 활용

```bash
# 기본 조회
nslookup target.com           # 기본 A 레코드 조회
nslookup -type=any target.com # 모든 레코드 조회

# 대화형 모드
nslookup
> server 8.8.8.8              # DNS 서버 설정
> set type=MX                 # 레코드 타입 설정
> target.com                  # 도메인 쿼리
> exit                        # 종료

# WHOIS 정보 수집
whois target.com              # 도메인 등록 정보
whois 10.10.10.10             # IP 소유 정보
```

## DNS 존 전송 (Zone Transfer)

```bash
# 네임서버 먼저 찾기
host -t NS target.com

# 존 전송 시도 (dig)
dig @ns1.target.com target.com AXFR  # 각 네임서버 시도

# 존 전송 시도 (host)
host -l target.com ns1.target.com

# 하위 도메인 존 전송
dig @ns1.target.com subdomain.target.com AXFR

# 존 전송 스크립트
for ns in $(host -t NS target.com | cut -d " " -f4); do
    echo "Testing $ns"
    dig @$ns target.com AXFR
done
```

## 서브도메인 열거

```bash
# 수동 브루트포스
for sub in www mail ftp admin blog dev test; do
    host $sub.target.com | grep "has address"
done

# 서브도메인 스크립트
for sub in $(cat /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1000.txt); do
    host $sub.target.com | grep "has address" | tee -a found_subs.txt
done

# 와일드카드 탐지
host random123456.target.com
# 응답이 있으면 와일드카드 설정된 것
```

## 호스트 발견 기법

```bash
# IP 범위 역방향 조회
for ip in $(seq 1 254); do
    host 10.10.10.$ip | grep "domain name pointer"
done

# 여러 서브넷 스캔
for subnet in 10 11 12; do
    for host in $(seq 1 10); do
        host 10.10.$subnet.$host | grep "domain"
    done
done

# 발견된 호스트 정리
# 호스트명 추출
dig target.com ANY +noall +answer | grep -v "^;" | awk '{print $1}'

# IP 주소 추출
dig target.com ANY +noall +answer | grep -v "^;" | awk '{print $5}'
```

## 정보 노출 탐지

```bash
# DNS 서버 버전 정보 노출
dig @ns1.target.com version.bind CHAOS TXT
dig @ns1.target.com hostname.bind CHAOS TXT

# 내부 IP 주소 노출 검사
dig target.com ANY | grep -E '(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)'

# SPF/DMARC 레코드 확인
dig target.com TXT | grep "v=spf"
dig _dmarc.target.com TXT
```

## 실전 활용 기법

```bash
# DNS 정보 시각화
# 1. 먼저 네임서버 찾기
ns=$(dig target.com NS +short)

# 2. 존 전송 시도
for nameserver in $ns; do
    dig @$nameserver target.com AXFR > zone_$nameserver.txt
done

# 3. 발견된 서브도메인 포트 스캔
for sub in $(grep -E "^[a-zA-Z0-9].*\.target\.com\." zone_*.txt | awk '{print $1}'); do
    echo "Scanning $sub"
    nmap -Pn -sT -p 80,443,8080,8443 $sub
done
```

## DNS 캐시 스누핑

```bash
# 캐시 정보 확인
dig @dns.target.com +norecurse target.com

# 특정 레코드 캐시 확인
dig @dns.target.com +norecurse mail.target.com MX

# 캐시 TTL 분석
ttl1=$(dig @dns.target.com target.com | grep "^target.com" | awk '{print $2}')
sleep 60
ttl2=$(dig @dns.target.com target.com | grep "^target.com" | awk '{print $2}')
echo "첫 번째 TTL: $ttl1, 두 번째 TTL: $ttl2"
```

## DNS 체크리스트

### 기본 정보 수집

```
□ A/AAAA 레코드 (IP 주소)
□ NS 레코드 (네임서버)
□ MX 레코드 (메일 서버)
□ TXT 레코드 (SPF/DMARC 등)
□ SOA 레코드 (관리 정보)
```

### 고급 수집

```
□ 존 전송 취약점 테스트 (AXFR)
□ 서브도메인 열거
□ 내부 IP 주소 노출 여부
□ DNS 캐시 분석
□ 이메일 인프라 검사
```

### 데이터 활용

```
□ 발견된 호스트 정리 및 문서화
□ 호스트별 포트스캔
□ 웹 서비스 확인
□ 네트워크 범위 추정
□ 내부 시스템 구조 파악
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
