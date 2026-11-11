# ssh_key_gen / ssh 접속

> 무엇: ssh-keygen으로 ed25519(권장)·RSA 4096 키 쌍을 만들고 ssh-copy-id로 공개키를 타깃 authorized_keys에 등록해 키 기반 SSH 접속을 여는 절차
> 언제: SSH 계정 크리덴셜을 확보해 지속 접속 수단을 만들 때, 또는 획득한 개인 키로 ssh -i 접속을 시도할 때
> 조건: 타깃 SSH 포트 접근 가능(비표준은 -p), ssh-keygen·ssh 설치, 키 등록에는 대상 계정의 authorized_keys 쓰기 권한, 접속에는 개인 키 파일 필요(실전에서는 -N ""로 패스워드 없는 키를 쓴다)

## 개요

SSH 키를 생성하고, 공유키(공개키)를 타깃에 올려두는 것은 크리덴셜 공격의 전제다. 키 생성 방법과 접속에 필요한 옵션을 정리한다.

## 키 생성

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
```

- `-t`: 알고리즘 (ed25519 권장, RSA는 4096)
- `-f`: 파일 이름 (디렉터리에 저장됨)
- `-N`: 빈 비밀번호 (OSCP 실전에서는 비밀번호를 쓰지 않는다)

## 공개키 확인 / 전송

```bash
cat ~/.ssh/id_ed25519.pub   # 공개키 내용
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@target   # 타깃의 authorized_keys에 추가
```

## ssh 접속 시 자주 쓰는 옵션

```bash
ssh -i ~/.ssh/id_ed25519 user@10.10.10.10
ssh -p 2222 -i ~/.ssh/id_ed25519 user@10.10.10.10   # 비표준 포트
ssh -o BatchMode=yes user@10.10.10.10            # 비밀번호 없이 시도 (실패하면 바로 종료)
```

## 결과 해석

- 접속이 안 되면 (a) 키가 올라갔는지, (b) 포트가 22가 아닌지, (c) 사용자 이름이 틀렸는지 확인한다.
- `BatchMode=yes`를 붙여두면 비밀번호 프롬프트가 나타나지 않아, 스크립트/자동화에 유용하다.
- `ssh -v`를 붙이면 접속 실패 지점을 확인할 수 있다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
