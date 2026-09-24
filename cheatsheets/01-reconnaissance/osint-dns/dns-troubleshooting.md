## TryHackMe Takeover 문제 분석 - SSL 인증서를 통한 서브도메인 발견

### 초기 에러 분석
`ERR_SSL_KEY_USAGE_INCOMPATIBLE` 에러가 발생했습니다. 이 에러는 SSL 인증서의 Key Usage 필드가 웹 서버용으로 올바르게 설정되지 않았음을 의미합니다. 브라우저가 인증서를 신뢰하지 않아 접속을 차단한 것입니다.

### SSL 문제 파악 경위
단계적 진단을 통해 문제를 파악했습니다:
1. `DNS_PROBE_FINISHED_NXDOMAIN` → hosts 파일 문제 해결
2. `ERR_SSL_KEY_USAGE_INCOMPATIBLE` → SSL 인증서 문제 확인
3. `curl -k` 옵션으로 SSL 검증 우회 → 정상 접속 확인

SSL 문제를 확실히 인지한 이유는 `curl -k` (SSL 검증 무시)로는 접속이 성공했지만 브라우저에서는 SSL 에러로 차단되었기 때문입니다. 이는 Certificate transparency 분석이 필요한 상황임을 의미했습니다.

### OpenSSL 명령어 사용 경위
왜 OpenSSL을 사용했는가:
1. 브라우저 SSL 에러로 인해 인증서 직접 분석 필요
2. Subdomain Takeover 문제 특성상 SAN(Subject Alternative Names) 확인 필요  
3. curl -v의 한계로 인증서 상세 정보 부족
4. OpenSSL로 인증서의 모든 필드 분석 가능

### OpenSSL 명령어 토큰별 분석

```bash
echo | openssl s_client -servername support.futurevera.thm -connect 10.201.81.37:443 2>/dev/null | openssl x509 -text -noout
```

**1단계: `echo |`**
- 목적: 빈 입력을 제공
- 이유: openssl s_client가 대화형 모드로 실행되는 것을 방지
- 효과: 자동으로 연결 후 즉시 종료

**2단계: `openssl s_client`**
- `openssl`: OpenSSL 도구 실행
- `s_client`: SSL/TLS 클라이언트 모드 (서버에 연결하는 클라이언트 역할)
- `-servername support.futurevera.thm`: SNI (Server Name Indication) 설정. 하나의 IP에서 여러 SSL 인증서를 호스팅하는 경우 서버에게 어떤 도메인의 인증서를 요청하는지 알려줌
- `-connect 10.201.81.37:443`: 연결할 IP주소와 포트 지정 (443은 HTTPS 기본 포트)
- `2>/dev/null`: 표준 에러(stderr) 출력을 버려서 불필요한 에러 메시지 숨김

**3단계: 파이프 `|`**
- 목적: 첫 번째 명령어 출력을 두 번째 명령어 입력으로 전달
- 전달되는 데이터: SSL 인증서 정보 (PEM 형식)

**4단계: `openssl x509`**
- `openssl`: OpenSSL 도구 재실행
- `x509`: X.509 인증서 처리 모드
- `-text`: 인증서를 사람이 읽을 수 있는 텍스트 형식으로 출력하여 모든 필드를 상세히 표시
- `-noout`: PEM 형식의 원본 인증서 데이터 출력 억제하여 `-text` 옵션으로 파싱된 결과만 출력

### 전체 명령어의 동작 흐름
1. 연결 설정: `echo |`로 자동 입력 제공하며 SSL 서버에 연결
2. 인증서 수신: 서버에서 SSL 인증서를 받아옴
3. 데이터 전달: 받은 인증서를 파이프를 통해 x509 명령어로 전달
4. 파싱 및 출력: 인증서의 모든 필드를 사람이 읽기 쉬운 형태로 변환하여 출력

### 핵심 발견사항
Subject Alternative Name에서 숨겨진 서브도메인을 발견했습니다:
```
X509v3 Subject Alternative Name: 
    DNS:secrethelpdesk934752.support.futurevera.thm
```

이 명령어를 통해 숨겨진 서브도메인을 발견할 수 있었고, 이것이 바로 Subdomain Takeover 공격의 핵심이었습니다.

### 왜 이 방법이 효과적인가
1. **완전한 인증서 분석**: 브라우저나 curl로는 보기 어려운 SAN, Key Usage, Extended Key Usage 등 모든 확장 필드까지 분석 가능
2. **자동화 친화적**: 스크립트에서 사용하기 용이하고 파이프라인을 통한 연쇄 처리 가능
3. **에러 회피**: SSL 검증 에러와 관계없이 인증서 정보 획득 가능하며 `2>/dev/null`로 불필요한 에러 메시지 제거

### 보안 관점에서의 의미
이 기법은 Certificate Transparency를 활용한 정보 수집 기법으로, 합법적인 정찰 기법이자 OSINT(오픈 소스 인텔리전스)의 일종입니다. 잘못 설정된 인증서에서 추가 공격 표면을 발견할 수 있습니다.

### 핵심 요약
문제 해결 체인은 다음과 같습니다:
1. 브라우저 SSL 에러 → SSL 인증서 문제 인식
2. curl -k 성공 → 인증서는 존재하지만 설정 문제 확인
3. OpenSSL 사용 → 인증서 상세 분석 필요성 인식
4. SAN 필드 발견 → 숨겨진 서브도메인 `secrethelpdesk934752.support.futurevera.thm` 발견
5. 최종 플래그 → 새 도메인에서 AWS S3 리다이렉트로 플래그 획득

학습 포인트는 SSL 에러 자체가 힌트가 될 수 있다는 점, SSL 인증서는 공개 정보이므로 정찰에 활용할 수 있다는 Certificate Transparency 개념, 그리고 OpenSSL이 네트워크 보안 분석의 핵심 도구라는 점입니다. 이것이 바로 Subdomain Takeover 공격의 정찰 단계에서 사용되는 고전적이면서도 효과적인 기법입니다.