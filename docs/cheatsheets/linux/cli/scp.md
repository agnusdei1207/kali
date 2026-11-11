> 무엇: SSH 채널로 로컬과 타깃 사이 파일을 복사하는 scp의 송신·수신 예시와, 호스트 키가 바뀐 타깃 기록을 지우는 ssh-keygen -R을 모은 메모
> 언제: 익스플로잇·도구를 타깃에 올리거나 flag·덤프 파일을 내려받을 때, 그리고 "REMOTE HOST IDENTIFICATION HAS CHANGED" 경고로 접속이 막힐 때 꺼낸다
> 조건: 양쪽 모두 SSH로 접근 가능해야 하고 접속 계정의 사용자명·비밀번호(또는 키)가 필요하다. 예시는 Windows 타깃 경로(C:\Users\...)를 쓴다

```bash
# local to target
scp 파일이름 jeff@192.168.80.200:C:\Users\jeff\Desktop\

# target to local
scp jeff@192.168.80.200:C:\path\to\file.txt .
```

```bash
# reset ssh config
ssh-keygen -R 123.123.123.123
```
