# sslyze TLS 스캐닝

- sslyze — Python 기반 SSL/TLS 스캐너. 인증서, 압축(CRIME), Heartbleed, 세션 재개 등 개별 검사 명령을 조합해 스캔하고 결과를 JSON으로 받을 수 있다.
- sslscan으로 열거한 뒤 CRIME·Heartbleed·세션 재개 같은 개별 검사를 정확히 뽑아 볼 때, 인증서 검증 결과를 확인할 때, 스캔 결과를 JSON으로 후처리할 때.
- Python 도구. Kali는 apt install sslyze, pip는 pip install sslyze. 의존성 충돌을 피하려면 venv 사용을 권장.

## 기본 명령어 구조

```bash
sslyze [검사옵션] HOST:PORT
```

## 인증서 검사 (--certinfo)

```bash
sslyze --certinfo 10.10.10.10:443
```

- 서버 인증서를 파싱해 발급자, 유효기간, SAN, 체인 검증 결과를 출력한다.
- --certinfo_ca_file <파일>로 자체 CA를 지정해 검증 기준을 바꿀 수 있다.

## 압축·Heartbleed·세션 재개

```bash
sslyze --compression 10.10.10.10:443      # TLS 압축 (CRIME)
sslyze --heartbleed 10.10.10.10:443       # OpenSSL Heartbleed
sslyze --resum 10.10.10.10:443            # 세션 재개 (session id + TLS ticket)
sslyze --resum --resum_attempts 10 10.10.10.10:443
```

- --resum은 TLS 1.2 세션 재개 지원 여부를 session id와 ticket 두 경로로 확인한다. 재개 실패가 많으면 성능 문제, 재개 전부 성공·지나치게 관대하면 설정 점검 대상이다.
- --resum_attempts로 재시도 횟수를 늘려 판정 신뢰도를 높인다(기본 5).

## 프로토콜 버전 검사

```bash
sslyze --tlsv1 --tlsv1_1 10.10.10.10:443     # 구형 프로토콜 수용 여부
sslyze --tlsv1_2 10.10.10.10:443
sslyze --tlsv1_3 10.10.10.10:443
```

- 각 버전 플래그는 해당 버전으로 핸드셰이크해 지원 여부와 암호 스위트를 확인한다.
- TLSv1.0·1.1이 성공하면 testssl.sh -p로 후속 확인을 권장한다.

## JSON 출력

```bash
sslyze --certinfo --heartbleed 10.10.10.10:443 --json_out result.json
sslyze --certinfo 10.10.10.10:443 --json_out -
```

- --json_out <파일>로 결과를 JSON 문서로 저장한다. 값을 -로 주면 stdout에 JSON을 출력해 파이프 후처리가 가능하다.

## 실전 예시

```bash
# 여러 검사 한 번에 실행
sslyze --certinfo --compression --heartbleed --resum 10.10.10.10:443

# 결과 파일로 저장
sslyze --certinfo --compression --heartbleed 10.10.10.10:443 --json_out sslyze.json

# 여러 대상 동시 스캔
sslyze --certinfo 10.10.10.10:443 10.10.10.11:443
```

## venv로 최신 버전 실행

```bash
python3 -m venv ~/venvs/sslyze
source ~/venvs/sslyze/bin/activate
pip install sslyze
sslyze --certinfo 10.10.10.10:443
```

- Kali 패키지 버전이 오래되면 venv + pip 최신판을 쓴다. Windows에서도 python이 있으면 같은 방식으로 동작한다.

## 팁·트러블슈팅

- 세션 재개 옵션 철자는 --resum이다. --resume이 아니다. 옵션 오류는 무조건 usage 출력으로 끝난다.
- 인증서만 필요하면 --certinfo 하나면 충분하다. 검사 옵션을 지정한 것만 실행된다.
- 검사 옵션을 하나도 주지 않으면 어떤 검사도 의미가 없어진다 — 최소 하나 이상 지정한다.
- CDN·로드밸런서 뒤 대상은 노드마다 설정이 다를 수 있다. 같은 도메인을 반복 스캔해 결과가 다르면 노드 편차를 의심한다.
