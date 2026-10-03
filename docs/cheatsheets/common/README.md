# Common Tools & Formats (공통 도구 및 형식)

명령어, 인코딩, 데이터 포맷 등 모든 단계에서 자주 사용하는 도구와 기법을 정리합니다.

## 폴더 구조

```
common/
├── cryptography/       → 해시, 암호화, 인코딩 (기존)
├── linux-cli/          → Linux 기본 명령어 (기존)
├── bash/               → Bash 스크립팅 (기존)
├── scripts/            → 스크립트 유틸 (기존)
├── lab-setup/          → 랩 환경 설정 (기존)
├── markup/             → 마크업 언어 (NEW!)
├── ENCODING_DECODING_REFERENCE.md → 통합 인코딩 가이드 (NEW!)
└── README.md           → 이 파일
```

---

## 📚 인코딩 & 암호화 (Encoding & Cryptography)

### 한 파일에서 모두 찾기

**[ENCODING_DECODING_REFERENCE.md](./ENCODING_DECODING_REFERENCE.md)**

Base64, URL Encoding, ASCII, Hex, ROT13, HTML Entity 등 모든 인코딩 방법이 한곳에 정리되어 있습니다.

빠른 참고 테이블:
| 형식 | 복호화 가능 | 상세 |
|------|-----------|------|
| Base64 | ✅ | 텍스트/바이너리 전송 |
| URL Encoding | ✅ | URL 안전 전송 |
| ASCII | ✅ | 문자 ↔ 코드 변환 |
| Hex | ✅ | 바이너리 표현 |
| ROT13 | ✅ | 간단한 치환 |
| MD5/SHA | ❌ | 일방향 해시 |

### 개별 파일

- [base64.md](./cryptography/base64.md) - Base64 상세
- [ascii.md](./cryptography/ascii.md) - ASCII 및 Hex
- [hashid.md](./cryptography/hashid.md) - 해시 식별
- [md5sum.md](./cryptography/md5sum.md) - MD5/해시

---

## 🏷️ 마크업 언어 (Markup Languages)

### HTML - [HTML_REFERENCE.md](./markup/HTML_REFERENCE.md)

웹 페이지 구조 분석, 스크래핑

주요 도구:
- **BeautifulSoup**: Python에서 HTML 파싱 (가장 쉬움)
- **lxml**: 더 빠른 파싱
- **Pandas**: 테이블 자동 추출

보안:
- XSS 방지: HTML escape 필수
- 스크래핑: robots.txt 확인

### Markdown - [MARKDOWN_REFERENCE.md](./markup/MARKDOWN_REFERENCE.md)

문서 작성, GitHub, 기술 블로그

변환 도구:
- **Pandoc**: 가장 강력한 형식 변환
- **Python markdown**: 간단한 변환
- **markdownify**: HTML → Markdown

---

## 🔧 Linux CLI 명령어

### 기본 명령어

기존 파일 참고:
- [find.md](./linux-cli/find.md) - 파일 검색
- [grep.md](./linux-cli/grep.md) - 텍스트 검색
- [vim.md](./linux-cli/vim.md) - 텍스트 편집
- [sed.md](./linux-cli/sed.md) - 스트림 편집 (기존)

### 데이터 처리

텍스트 필터링 및 변환:
- [tr.md](./linux-cli/tr.md) - 문자 치환 (ROT13 등)
- [jq.md](./linux-cli/jq.md) - JSON 파싱 (별도 파일)
- [awk.md](./linux-cli/awk.md) - 고급 텍스트 처리 (기존)

### 압축

- [tar.md](./linux-cli/tar.md) - 아카이브
- [gzip.md](./linux-cli/gzip.md) - 압축
- [zip_unzip.md](./linux-cli/zip_unzip.md) - ZIP 파일

---

## 🐚 Bash 스크립팅

### 기본 문법

- [bash_overview.md](./bash/bash_overview.md) - 개요
- [bash_syntax.md](./bash/bash_syntax.md) - 문법
- [if.md](./bash/if.md) - 조건문
- [loop.md](./bash/loop.md) - 반복문

### 실무 스크립트

- [brute_force.md](./bash/brute_force.md) - 무차별 대입

---

## 🔐 인증 & 암호화 (Cryptography)

### 해시 및 암호화 (복호화 불가)

- [md5sum.md](./cryptography/md5sum.md) - MD5/해시 생성
- [hashid.md](./cryptography/hashid.md) - 해시 타입 식별

### 인코딩 (복호화 가능)

- [base64.md](./cryptography/base64.md) - Base64
- [ascii.md](./cryptography/ascii.md) - ASCII/Hex
- [dh.md](./cryptography/dh.md) - Diffie-Hellman
- [rsa.md](./cryptography/rsa.md) - RSA 암호화

---

## 📋 스크립트 유틸

기존 파일:
- [url_encode_decode.md](./scripts/url_encode_decode.md)
- [javascript_url_encode.md](./scripts/javascript_url_encode.md)
- [python_server.md](./scripts/python_server.md)
- [javascript_fetch.md](./scripts/javascript_fetch.md)

---

## 🛠️ 랩 환경 설정

- [git.md](./lab-setup/git.md) - Git 설정
- [docker_install.md](./lab-setup/docker_install.md) - Docker
- [python_venv.md](./lab-setup/python_venv.md) - Python 가상환경
- [open_vpn.md](./lab-setup/open_vpn.md) - VPN 연결

---

## 🎯 사용 시나리오별 빠른 선택

### API 응답 처리
→ JSON_REFERENCE.md + jq

### 웹 스크래핑
→ HTML_REFERENCE.md + BeautifulSoup

### 데이터 변환
→ ENCODING_DECODING_REFERENCE.md

### 설정 파일
→ YAML_CSV_REFERENCE.md

### 스크립트 작성
→ bash_overview.md + [필요한 도구]

### 보안 해시
→ cryptography/md5sum.md, hashid.md

---

## 📖 학습 경로

초급:
1. [ENCODING_DECODING_REFERENCE.md](./ENCODING_DECODING_REFERENCE.md) - 기본 인코딩
2. [bash_overview.md](./bash/bash_overview.md) - 쉘 기본
3. [linux-cli](./linux-cli/) - 명령어 기초

중급:
4. [JSON_REFERENCE.md](./data-formats/JSON_REFERENCE.md) - 데이터 포맷
5. [HTML_REFERENCE.md](./markup/HTML_REFERENCE.md) - 웹 분석
6. [YAML_CSV_REFERENCE.md](./data-formats/YAML_CSV_REFERENCE.md) - 설정 파일

고급:
7. [XML_REFERENCE.md](./data-formats/XML_REFERENCE.md) - XML 처리
8. [MARKDOWN_REFERENCE.md](./markup/MARKDOWN_REFERENCE.md) - 문서 자동화
9. [cryptography/](./cryptography/) - 암호화 및 해싱

---

## 💡 팁

### 빠른 변환

```bash
# Base64
echo "text" | base64

# URL 인코딩
python3 -c "import urllib.parse; print(urllib.parse.quote('text'))"

# JSON 포맷팅
python3 -m json.tool < input.json

# Hex 변환
echo -n "text" | xxd -p
```

### 파이프 활용

```bash
# curl → jq → grep
curl -s https://api.example.com/data | jq '.[]' | grep "pattern"

# 파일 → base64 → 저장
cat file.txt | base64 > file.b64

# 웹 페이지 → HTML 파싱 → 추출
curl -s https://example.com | python3 -c "from bs4 import BeautifulSoup; import sys; soup = BeautifulSoup(sys.stdin, 'html.parser'); print(soup.title)"
```

---

## 📞 관련 링크

- 상위: [cheatsheets/README.md](../README.md)
- 다른 카테고리: [01-reconnaissance](../01-reconnaissance/), [02-vulnerability-analysis](../02-vulnerability-analysis/) 등
- 메인: [docs/README.md](../../README.md)

---

마지막 업데이트: 2026-10-03
