# sslscan TLS·암호 스위트 열거

- sslscan — 대상 서버의 지원 TLS 버전과 암호 스위트를 몇 초 만에 열거하는 C 도구. 결과에서 비활성·취약 항목이 바로 눈에 들어온다.
- 443 포트 발견 직후 TLS 구성을 빠르게 훑을 때, TLSv1.0/1.1 같은 구형 프로토콜과 RC4·3DES 같은 취약 암호 허용 여부를 확인할 때, 인증서 요약(알고리즘·만료·SAN)을 볼 때.
- apt install sslscan. 대상 형식은 host[:port], 포트 생략 시 443.

## 기본 명령어 구조

```bash
sslscan [옵션] HOST:PORT
```

## 기본 실행

```bash
sslscan 10.10.10.10:443
sslscan target.example.com
sslscan 10.10.10.10:8443
```

- 실행 순서로 버전 정보, TLS Callbacks, SSL Certificate, Protocol Support, Cipher Suites가 출력된다.

## 결과 해석 — 프로토콜

```text
  Protocol Support:
    SSLv2     Disabled
    SSLv3     Disabled
    TLSv1.0   Enabled   (deprecated)
    TLSv1.1   Enabled   (deprecated)
    TLSv1.2   Enabled
    TLSv1.3   Enabled
```

- Enabled(deprecated)로 표시되는 TLSv1.0/1.1이 1차 finding이다. SSLv3, SSLv2가 Enabled면 심각 finding.
- Cipher Suites 섹션에서 RC4, 3DES, NULL, EXPORT 계열이 Accepted면 finding이다.

## 인증서 보기 (--show-certificate)

```bash
sslscan --show-certificate 10.10.10.10:443
```

- Signature Algorithm(sha1WithRSA 등), RSA 키 크기, 만료일, SAN, 체인 요약이 출력된다.
- sha1 서명, 1024bit 키, 만료 임박이면 testssl.sh로 후속 정밀 점검을 이어간다.

## 주요 옵션

- `--no-colours`: 색상 코드 제거. 리다이렉트·보고서용.
- `--show-certificate`: 인증서 상세 출력.
- `--no-failed`: Rejected(실패) 암호를 생략하고 Accepted만 표시.
- `--xml <file>`: 결과를 XML로 저장.
- `--ssl2 --ssl3 --tls10 --tls11 --tls12 --tls13`: 특정 프로토콜 버전만 테스트.
- `--starttls-https, --starttls-smtp, --starttls-ftp...`: starttls 계열 포트 점검.
- `--show-times`: 핸드셰이크 시간 측정 추가.

```bash
sslscan --no-colours --show-certificate 10.10.10.10:443 > sslscan_out.txt
sslscan --no-failed 10.10.10.10:443
sslscan --starttls-smtp 10.10.10.10:25
sslscan --xml sslscan.xml 10.10.10.10:443
```

## testssl.sh와의 비교

- sslscan: 빠르다. 프로토콜·암호 열거와 인증서 표시가 중심이다. Heartbleed·CCS 같은 취약점 점검은 없다.
- testssl.sh: 느리지만 인증서 체인 검증, 취약점, starttls까지 종합 점검한다.
- 실전 흐름: sslscan으로 1차 훑기, 이상 징후를 testssl.sh로 정밀 확인.

## 팁·트러블슈팅

- 결과를 파일로 저장하면 색상 코드가 섞인다. --no-colours를 습관처럼 붙인다.
- SNI가 필요한 가상호스트는 hostname으로 대상을 지정해야 인증서와 스위트가 정확히 나온다.
- 모든 프로토콜이 Disabled로 나오면 대상이 TLS가 아닌 다른 서비스일 가능성. nmap 서비스 판정을 재확인한다.
- 암호 스위트 목록이 비정상적으로 짧으면 중간 장비(프록시·WAF)가 끼어 있을 수 있다.
