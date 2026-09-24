# SCP Command Reference

## Basic Usage

SCP (Secure Copy Protocol) allows secure file transfer between hosts.

### File Transfer Examples

**Download a file from remote server to local machine:**

```bash
scp -i test.pem ubuntu@123.123.123.123:/home/ubuntu/backups/test.dump C:/workspace/test/
```

**Connect to remote server with key:**

```bash
ssh -i workspace/private-keys/t.pem ubuntu@123.123.123.123
```

## Troubleshooting

### Host Key Verification Failed

When you see this error:

```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
```

**Possible causes:**

- IP has been reassigned to a different machine
- Host operating system was reinstalled
- SSH server was reinstalled/reconfigured
- You're connecting to a different machine with the same IP
- (Worst case) Man-in-the-middle attack

### Solutions

**Option 1: Remove the offending key (if you're sure it's safe):**

```bash
sed -i '54d' /c/Users/tester/.ssh/known_hosts
```

이 명령어는 SSH 호스트 키 검증 실패 문제를 해결하기 위해 known_hosts 파일에서 특정 줄을 삭제하는 명령입니다.

상세 분석:
sed: Stream EDitor의 약자로, 텍스트 파일을 처리하는 강력한 유닉스 도구입니다.
-i: "in-place"(제자리) 옵션으로, 출력 결과를 다른 파일이 아닌 원본 파일에 직접 적용합니다.
'54d': sed 편집 명령입니다.
54: 54번째 줄을 대상으로 합니다.
d: delete(삭제) 명령입니다.
/c/Users/tester/.ssh/known_hosts: 편집할 대상 파일 경로입니다

실무적 의미:
서버 재설치나 IP 재할당 등의 정당한 이유로 SSH 호스트 키가 변경되었을 때, 이 명령어로 이전 키 정보를 삭제하여 새로운 연결을 허용할 수 있습니다. 보안 경고를 제거하는 간단한 방법이지만, 실제 중간자 공격 가능성이 있는 경우에는 주의해서 사용해야 합니다.

**Option 2: Update the host key (safer approach):**

```bash
ssh-keygen -R 123.123.123.123
```

_This removes all keys for the host and prompts for new key verification on next connection_
