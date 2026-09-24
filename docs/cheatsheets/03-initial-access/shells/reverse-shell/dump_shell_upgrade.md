### ✅ 원인: `su`는 **TTY (가상 터미널)** 가 필요합니다.

- `su`는 **비밀번호 입력을 위해 /dev/tty 또는 stdin이 TTY인지 검사**합니다.
- 리버스 쉘은 기본적으로 TTY가 **없기 때문에**, 비밀번호 입력 처리를 못 해서 **그냥 멈춰있는 것처럼 보입니다.**

### ✔️ 1. Python을 통한 TTY 업그레이드

리버스 쉘에서 아래 명령어를 실행:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

### ✔️ 2. `stty` 오류 방지 (선택)

```bash
export TERM=xterm
```

---

### ✔️ 3. 백그라운드로 전환 후 `fg`로 복원 (netcat일 경우에만)

1. 백그라운드 전환:
   Ctrl+Z

2. 터미널 로 설정 및 복귀:

```bash
stty raw -echo; fg
```



