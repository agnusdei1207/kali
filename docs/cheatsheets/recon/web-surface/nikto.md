# nikto

## 개요

`nikto`는 웹 서버의 취약점을 스캔하는 도구이다. 서버 설정, 위험 파일, 오래된 소프트웨어 등을 탐지한다.
OSCP 웹 공격 단계의 초기 정찰에 쓰인다.

## 설치

```bash
sudo apt update
sudo apt install nikto -y
```

## 사용법

```bash
nikto -h http://192.168.1.10:80
nikto -h https://target.thm -port 443
nikto -h http://target.thm -C all
```

## 주요 옵션

| 옵션 | 설명 |
|------|------|
| `-h <host>` | 대상 호스트 |
| `-p <port>` | 포트 (기본 80) |
| `-C <category>` | 검사 카테고리 (예: all) |
| `-o <file>` | 출력 파일 |
| `-F <format>` | 출력 형식 (htm, csv, txt, xml) |

## 결과 해석

- "OSVDB-xxxxx" 항목이 공개된 취약점 참조 번호다.
- 탐지된 파일(예: `/admin`, `/test`)은 이후 직접 확인 대상으로 삼는다.
- nikto 결과만으로 공격하지 않고, 이후 수동 확인(whatweb, 수동 페이로드 테스트)을 병행한다.

## 팁

- nikto는 소음이 큰 도구이다. IDS/IPS가 있는 환경에서는 탐지될 수 있다.
- 결과는 노트(05-progress-tracker)에 발견 항목과 함께 적는다.
