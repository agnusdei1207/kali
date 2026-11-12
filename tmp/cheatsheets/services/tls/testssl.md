# testssl.sh TLS 설정 종합 점검

- testssl.sh — TLS/SSL 설정(프로토콜·암호 스위트·인증서·알려진 취약점)을 쉘 스크립트 하나로 광범위하게 점검하는 도구. 내부적으로 openssl을 호출한다.
- 443 포트 발견 직후 TLS 구성을 종합 점검할 때, 구형 프로토콜·암호 허용 여부를 확인할 때, 인증서 체인·만료·SAN과 starttls(SMTP 등)까지 볼 때.
- Kali 패키지명이 testssl.sh이고 실행 파일도 testssl.sh(확장자 포함)이다. apt install testssl.sh로 설치.

## 기본 명령어 구조

```bash
testssl.sh [옵션] URI
```

## 기본 실행

```bash
testssl.sh 10.10.10.10:443
testssl.sh https://target.example.com
testssl.sh --quiet 10.10.10.10:443 > report.txt
```

- 옵션 없이 실행하면 프로토콜, 암호 스위트, 서버 기본 설정, 인증서, 취약점(Heartbleed, CCS 등)을 순서대로 점검한다.
- --quiet은 진행 로그를 줄여 결과만 남긴다. 리다이렉트할 때 권장.

## 프로토콜 점검 (-p)

```bash
testssl.sh -p 10.10.10.10:443
```

- TLS 1.0~1.3, SSLv3 등의 지원 여부를 "offered / not offered"로 출력한다.
- TLSv1.0·TLSv1.1이 offered면 finding이고, SSLv3 offered는 즉시 수정 대상이다.

## 암호 스위트 상세 (-e, -E)

```bash
# 각 암호를 개별 연결로 하나씩 테스트 (느림, 정확)
testssl.sh -e 10.10.10.10:443

# 프로토콜 x 암호 전체 행렬 (실전 기본형)
testssl.sh -E 10.10.10.10:443
```

- -E가 실전에서 빠르고 읽기 편하다. 서버 선호 순서(prio)까지 함께 표시된다.
- RC4, 3DES, NULL, EXPORT 계열이 offered면 finding이다.

## 심각도 기준 종료 코드 (--severity)

```bash
testssl.sh --severity LOW 10.10.10.10:443; echo exit=$?
```

- 지정한 심각도(LOW, MEDIUM, HIGH, CRITICAL) 이상 finding이 하나라도 있으면 종료 코드 2를 반환한다.
- 스크립트·CI 판정 조건으로 쓰기 좋다.

## openssl 연동

```bash
# 특정 openssl 바이너리 지정
testssl.sh --openssl /usr/local/bin/openssl 10.10.10.10:443

# testssl 자체 핸드셰이크 대신 openssl 네이티브 사용
testssl.sh --ssl-native 10.10.10.10:443
```

- 시스템 openssl이 오래되어 최신 TLS 1.3 스위트를 못 잡을 때 --openssl로 최신 빌드를 끼워 넣는다.

## 실전 예시

```bash
# 빠른 요약 + 결과 저장
testssl.sh --quiet --severity MEDIUM --wide 10.10.10.10:443 > tls_report.txt

# starttls 대상 (SMTP)
testssl.sh -t smtp 10.10.10.10:25

# 연결 타임아웃 조정
testssl.sh --connect-timeout 10 10.10.10.10:8443
```

## testssl.sh와 sslscan 비교

- testssl.sh: 점검 항목이 가장 넓다(인증서 체인, 취약점, starttls). 대신 느리다.
- sslscan, sslyze: 프로토콜·암호 열거가 빠르다. 1차 스캔용.
- 실전 흐름: sslscan으로 빠르게 훑고, testssl.sh로 정밀 점검하는 순서가 효율적이다.

## 팁·트러블슈팅

- Kali에 testssl이라는 명령은 없다. 바이너리 이름이 testssl.sh이므로 확장자까지 정확히 입력한다.
- --quiet 없이 리다이렉트하면 진행 로그까지 섞인다. 파일 저장 시 --quiet을 붙인다.
- 결과 해석 기준: "not offered"가 정상(안전)이고, "offered" + 낮은 등급 표시가 finding이다.
