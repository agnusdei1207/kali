## 1. `batcat` 설치 방법

### Ubuntu / Debian 계열

```bash
sudo apt update
sudo apt install batcat
```

---

## 2. `bat` 기본 사용법

- 파일 출력

```bash
bat 파일명.html
```

- 파이프로 연결해서 사용

```bash
curl http://example.com | bat -l html
```

`-l html` 은 하이라이트할 언어를 **HTML**로 지정하는 옵션입니다.

---

## 3. 리버스쉘 HTML 보기 예시

```bash
curl -L -H "Cookie: wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_..." http://www.smol.thm/wp-admin/profile.php?cmd=ls | tidy -i -q | bat -l html
```

---

## 4. `bat` 주요 옵션

| 옵션                         | 설명                                                           |
| ---------------------------- | -------------------------------------------------------------- |
| `-l <언어>`                  | 하이라이트할 언어 지정 (예: `-l html`, `-l json`, `-l python`) |
| `-p`                         | 페이징 없이 그대로 출력 (`cat`처럼 동작)                       |
| `-r <줄번호>`                | 특정 줄 범위만 출력 (예: `-r 10-20`)                           |
| `--color <WHEN>`             | 색상 사용 시점 지정 (`always`, `auto`, `never`)                |
| `-f`, `--files-with-matches` | 매칭되는 파일 이름만 출력 (grep 스타일)                        |
| `-H`                         | 라인 번호 출력 숨기기 (기본은 켜져 있음)                       |
| `--paging <WHEN>`            | 페이징 동작 설정 (`always`, `never`, `auto`)                   |
| `--style <스타일>`           | 출력 스타일 지정 (예: `full`, `header`, `plain`)               |

---

## 5. 지원하는 주요 하이라이트 언어 예시

- `bat -l html` (HTML)
- `bat -l json` (JSON)
- `bat -l python` (파이썬)
- `bat -l javascript` (자바스크립트)
- `bat -l yaml` (YAML)
- `bat -l sh` (쉘 스크립트)

전체 언어 목록은 아래 명령어로 확인 가능합니다.

```bash
bat --list-languages
```

---

## 6. 자주 쓰는 조합 예시

- HTML 정렬 + 하이라이트 출력

```bash
curl URL | tidy -i -q | bat -l html
```

- JSON 파일 하이라이트 + 라인번호 숨기기

```bash
bat -l json -H 파일명.json
```

- 특정 줄만 출력 (예: 10\~20줄)

```bash
bat -r 10-20 파일명.txt
```

- 페이징 없이 출력 (스크립트나 파이프에서 사용 시)

```bash
bat -p 파일명.html
```

---

필요하면 심볼릭 링크로 `batcat`을 `bat`으로 쓸 수도 있습니다.

```bash
sudo ln -s /usr/bin/batcat /usr/local/bin/bat
```

---
