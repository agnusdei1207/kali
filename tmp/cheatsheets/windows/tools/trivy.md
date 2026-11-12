# trivy로 취약점·시크릿·IaC 스캔

- trivy — 파일시스템, 컨테이너 이미지, git 리포지토리, IaC(Terraform·K8s 매니페스트)를 스캔해 OS 패키지 CVE, 라이브러리 취약점, 시크릿, 설정 오류를 찾는 올인원 스캐너.
- 서버·호스트의 패키지 취약점을 빠르게 뽑을 때, 도커 이미지 배포 전 스캔을 돌릴 때, 코드에 하드코딩된 시크릿과 IaC 설정 오류를 확인할 때.
- Kali는 apt install trivy, Windows는 workspace\windows\tools\trivy\trivy.exe (또는 PATH). 취약점 DB를 처음 실행 시 내려받으므로 인터넷 연결이 필요하다.

## 기본 명령어 구조

```bash
trivy <대상종류> <대상> [옵션]
# 대상종류: fs(파일시스템), image, repo 등
```

## 파일시스템 스캔

```bash
trivy fs .
trivy fs --severity HIGH,CRITICAL .
trivy fs --scanners vuln,secret,misconfig .
trivy fs /home/user/app
```

- OS 패키지(apt·yum)와 언어 라이브러리(package.json, pom.xml 등)의 CVE를 같이 본다.

## 컨테이너 이미지 스캔

```bash
trivy image nginx:latest
trivy image --severity HIGH,CRITICAL --ignore-unfixed nginx:latest
trivy image --format json --output report.json nginx:latest
```

- `--ignore-unfixed`: 수정 가능한 버전이 없는 항목을 제외해 노이즈를 줄인다.

## IaC·시크릿 스캔

```bash
trivy fs --scanners misconfig,secret ./infra
trivy config ./terraform     # IaC 전용 하위 명령 (fs --scanners misconfig와 동일)
```

## 주요 옵션

- `--scanners vuln,secret,misconfig`: 수행할 스캔 종류 지정. 버전에 따라 기본값이 다르니 필요한 종류를 명시하는 게 안전하다.
- `--severity LOW,MEDIUM,HIGH,CRITICAL`: 표시할 심각도 필터.
- `--format json|sarif|html --output <파일>`: 리포트 형식과 출력 파일.
- `--skip-db-update`: 오프라인 실행 시 DB 갱신 생략.
- `--timeout <기간>`: 대상이 클 때 스캔 타임아웃 조정.

## 실전 예시

```bash
# Kali에서 로컬 호스트 취약점 점검
trivy fs --severity HIGH,CRITICAL --ignore-unfixed /

# 수집한 코드베이스·설정 스캔
trivy fs --scanners secret,misconfig /var/www/app

# 리포트 파일로 저장
trivy fs . --format html --output trivy-report.html
```

## 팁·트러블슈팅

1. 인터넷이 차단된 환경에서는 DB 업데이트 실패로 스캔이 안 된다. 연결된 호스트의 캐시 DB(~/.cache/trivy, Windows는 보통 %LocalAppData%\trivy)를 통째로 복사해 --skip-db-update로 실행한다.
2. 대상 디렉터리가 커지면 스캔이 느려진다. --timeout과 --severity 필터를 먼저 건다.
3. 오탐은 .trivyignore 파일에 CVE ID를 나열해 제외한다.
