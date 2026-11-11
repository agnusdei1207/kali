# Common (공통 도구·형식)

모든 카테고리에서 공용으로 쓰는 도구와 형식 모음이다.

## 폴더 구조

```
common/
├── crypto/     → 인코딩·암호화·해시
├── markup/     → HTML, Markdown 레퍼런스
├── lab-setup/  → 랩 환경 구성
├── scripts/    → 유틸 스크립트와 스크립트 노트
└── README.md   → 이 파일
```

## 인코딩·암호화 (crypto/)

한 번에 보기: [ENCODING_DECODING_REFERENCE.md](./ENCODING_DECODING_REFERENCE.md)

- [base64.md](./crypto/base64.md) - Base64 인코딩
- [ascii.md](./crypto/ascii.md) - ASCII·Hex
- [decode_ascii.md](./crypto/decode_ascii.md) - ASCII 디코딩
- [hashid.md](./crypto/hashid.md) - 해시 형식 식별
- [md5sum.md](./crypto/md5sum.md) - MD5 해시 생성
- [rsa.md](./crypto/rsa.md) - RSA 암호화
- [dh.md](./crypto/dh.md) - Diffie-Hellman

## 마크업 (markup/)

- [MARKDOWN_REFERENCE.md](./markup/MARKDOWN_REFERENCE.md) - Markdown 문법
- [HTML_REFERENCE.md](./markup/HTML_REFERENCE.md) - HTML 구조 분석
- [HTML_ENTITIES_REFERENCE.md](./markup/HTML_ENTITIES_REFERENCE.md) - HTML 엔티티

## 랩 환경 (lab-setup/)

- [base_install_apt_install.md](./lab-setup/base_install_apt_install.md) - 기본 패키지 설치
- [git.md](./lab-setup/git.md) - Git 설정
- [docker_install.md](./lab-setup/docker_install.md) - Docker
- [python_venv.md](./lab-setup/python_venv.md) - Python 가상환경
- [open_vpn.md](./lab-setup/open_vpn.md) - VPN 연결
- [os.md](./lab-setup/os.md) - OS 설정
- [rlwrap.md](./lab-setup/rlwrap.md) - rlwrap

## 스크립트 (scripts/)

- [python_server.md](./scripts/python_server.md) - python http.server 파일 서빙
- [url_encode_decode.md](./scripts/url_encode_decode.md) - URL 인코딩
- [javascript_url_encode.md](./scripts/javascript_url_encode.md) - JS URL 인코딩
- [javascript_fetch.md](./scripts/javascript_fetch.md) - JS fetch
- [fuzz_tcp_login.md](./scripts/fuzz_tcp_login.md) - TCP 로그인 퍼징
- [fuzz_tcp_find_password.md](./scripts/fuzz_tcp_find_password.md) - TCP 패스워드 탐색
- [yescript.md](./scripts/yescript.md) - yescript

관련 링크: [치트시트 인덱스](../README.md)
