# trufflehog를 이용한 검증된 시크릿 탐지

- trufflehog — Git 저장소·파일시스템·S3·Docker 이미지 등 수백 개 소스에서 시크릿을 찾고, 찾아낸 키를 실제 서비스 API에 접속해 유효성까지 확인(verified)하는 스캐너.
- 유출 조사에서 "이 키가 지금도 살아있는지"까지 확인해야 할 때. gitleaks가 정규식 기반 탐지인 것과 달리, 검증 단계까지 자동으로 돌릴 때.
- trufflehog 3.99.8 기준. 공식 설치 스크립트나 바이너리 배포판으로 설치한다(kali deb은 없을 수 있다). 검증은 실제 외부 서비스 API에 요청을 보내므로 네트워크가 막힌 환경에서는 verified 결과가 나오지 않는다.

## 기본 사용법

```bash
# git 저장소 스캔 (로컬 경로나 URL 모두 가능)
trufflehog git https://github.com/target/repo --only-verified
trufflehog git /path/to/repo

# 파일시스템 스캔 (경로는 위치 인자)
trufflehog filesystem /path/to/dir --only-verified
```

## 주요 옵션

- `git <대상>`: 커밋 히스토리 전체에서 시크릿 추출. https://, file://, ssh:// URI를 받는다.
- `filesystem <경로>`: 파일시스템 스캔. 파일이나 디렉터리 경로를 위치 인자로 준다(--directory는 deprecated).
- `--only-verified`: 검증에 성공한(실제 동작하는) 시크릿만 출력.
- `--results=verified`: 같은 역할의 최신 지정 방식. 기본값은 verified,unverified,unknown 전부 출력이다.
- `--json`: JSONL로 출력해 jq로 후처리.
- `--since-commit <hash>`: 이 커밋 이후만 스캔.
- `--branch <name>`: 대상 브랜치 지정.
- `--filter-entropy 3.0`: 엔트로피가 낮은 unverified 결과를 걸러낸다.

## 검증(verified) 개념

- unverified: 패턴이 맞지만 실제 유효한지는 미확인. gitleaks 수준의 결과.
- verified: 실제 API 호출로 키가 동작함을 확인. 이 키는 즉시 폐기 대상이다.
- 기본 출력에는 unverified가 섞여 나온다. 소음이 많으므로 1차 필터로 --only-verified(또는 --results=verified)를 쓰는 게 실용적이다.

## gitleaks와 비교

- gitleaks: 정규식 규칙 기반, 빠르고 설치가 쉬움, CI·pre-commit에 적합. 검증 기능 없음.
- trufflehog: 소스 커버리지가 넓고(S3, Docker, CI 로그 등) 검증 기능이 핵심. 외부 API 요청이 가능한 환경에서 유용.
- 실무 조합: gitleaks로 빠르게 전체를 훑고, trufflehog --only-verified로 지금 살아있는 키를 특정한다.

## 팁과 트러블슈팅

- 검증 요청은 대상 서비스에 직접 간다. 네트워크가 막힌 환경에서는 verified가 아예 안 나오므로 unverified까지 포함해 수동 확인한다.
- git 스캔은 히스토리 전체를 읽으므로 큰 저장소는 오래 걸린다. --since-commit으로 범위를 줄인다.
- Windows에서는 trufflehog.exe를 workspace\recon\trufflehog\에 두고 trufflehog.exe git C:\path\to\repo 형태로 실행한다.
