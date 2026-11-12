# gitleaks를 이용한 저장소 시크릿 스캔

- gitleaks — Git 저장소의 커밋 히스토리와 작업 디렉터리를 훑어 API 키·토큰·비밀번호 같은 시크릿이 하드코딩됐는지 정규식 기반 규칙으로 찾는 스캐너.
- 클론한 대상 저장소에서 유출된 키를 찾을 때, 내부 코드베이스를 커밋 전에 점검할 때(pre-commit), 여러 저장소를 일괄 점검할 때.
- gitleaks 8.30.1 기준. kali: sudo apt install gitleaks, Windows는 workspace\recon\gitleaks\gitleaks.exe. 결과에 실제 키 값이 그대로 찍히므로 공유용 리포트는 --redact를 붙인다.

## 기본 사용법

```bash
# 현재 디렉터리의 git 히스토리 전체 스캔 (8.19 이전 문법, 하위명령으로 대체 권장)
gitleaks detect --source . --redact

# 8.19+ 하위명령: git 히스토리 / 디렉터리(히스토리 제외)
gitleaks git /path/to/repo --redact
gitleaks dir /path/to/repo --redact
```

## 주요 옵션

- `git <경로>`: 커밋 히스토리 전체를 스캔. 삭제됐어도 커밋에 남아 있는 시크릿까지 본다.
- `dir <경로>`: 현재 파일만 스캔(git 없는 폴더도 가능). 8.19 이전의 detect --no-git에 해당.
- `--report-format json|sarif|csv|junit`: 리포트 형식. --report-path와 함께 쓴다.
- `--report-path leaks.json`: 리포트 저장.
- `--redact`: 발견된 시크릿 값을 마스킹. 결과를 공유할 때 필수.
- `--exit-code 1`: 발견 시 종료 코드(기본 1). CI에서 실패 신호로 쓴다.
- `--baseline-path baseline.json`: 기존에 승인된 발견 목록을 제외하고 신규만 보고.
- `--no-banner`: 시작 배너 숨김.

## 실전 예시

```bash
# SARIF 리포트로 남기기 (VS Code 등에서 열람 가능)
gitleaks git . --report-format sarif --report-path leaks.sarif --redact

# git 없는 대상 디렉터리 (백업 폴더, 덤프)
gitleaks dir /mnt/dump --report-format json --report-path dump_leaks.json --redact

# 대량 저장소 일괄 스캔
for d in /path/repos/*/; do gitleaks git "$d" --redact -v; done
```

## 팁과 트러블슈팅

- --redact를 빼먹으면 터미널·리포트에 실제 키가 그대로 남는다. 보고 형태로 나갈 때는 반드시 붙인다.
- false positive가 많으면(테스트용 더미 키 등) .gitleaks.toml의 allowlist로 제외한다. 규칙 커스터마이징도 이 설정 파일에서 한다.
- dir은 현재 파일만 보고 git은 히스토리까지 본다. 유출 조사 목적이면 git 스캔이 기본이다 — 히스토리에서 삭제됐어도 커밋이 남아 있으면 잡힌다.
- 발견된 키는 즉시 폐기·재발급이 원칙이고, 커밋에서 지우는 것만으로는 히스토리에 남는다.
