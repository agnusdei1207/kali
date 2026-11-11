# rsa

- ssh-keygen으로 RSA 4096·ed25519 키 페어를 생성하고 ssh-copy-id로 공개키를 타깃 authorized_keys에 등록하는 SSH 키 인증 정리다.
- 초기 침투에서 SSH 접근 경로를 확보하거나, 유출된 개인키 파일을 찾아 접속을 시도하는 크리덴셜 공격의 전제 단계에서 쓴다.
- 타깃에 SSH 접속 가능성이 필요하고 키는 비밀번호 없이(`-N ""`) 생성한다(ssh-keygen -t rsa -b 4096). ssh-copy-id 후 접속이 안 되면 키가 authorized_keys에 올라갔는지와 계정명부터 확인하고, 유출된 개인키는 즉시 삭제한다.

## 개요

RSA 키 페어의 공개키/개인키를 생성하고, 공개키를 타깃에 올려두는 것이 크리덴셜 공격의 전제다. OSCP 시험의 초기 침투 단계에서는 주로 키 생성 방법과 공개키 전송을 익히면 된다.

## 키 생성

```bash
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
```

- `-b 4096`: RSA 키 길이 (ed25519는 고정)
- `-N ""`: 빈 비밀번호 (OSCP에서는 비밀번호를 쓰지 않는다)
- `-f`: 저장 위치

## 키 확인

```bash
ls -l ~/.ssh/
cat ~/.ssh/id_rsa.pub     # 공개키
cat ~/.ssh/id_ed25519.pub
```

## 타깃에 공개키 전송

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@target
```

- `authorized_keys`에 추가된다.
- `ssh` 접속이 안 되면, 키가 올라갔는지, 계정 이름이 틀렸는지 확인한다.

## 실전 팁

- 여러 키를 준비해 두면, 어느 계정으로 접속할지 실험할 수 있다.
- 개인키가 유출됐다면 즉시 삭제한다 (`rm ~/.ssh/id_rsa`).

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
