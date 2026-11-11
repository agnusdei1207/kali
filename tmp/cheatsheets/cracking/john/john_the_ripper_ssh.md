# john the ripper ssh

- ssh2john.py로 암호 걸린 SSH 개인 키(id_rsa)의 패스프레이즈 해시를 추출해 john으로 크랙하는 절차 — /opt/john/run/ssh2john.py id_rsa > hash 후 john --wordlist=rockyou.txt
- 침투 테스트에서 SSH 개인 키를 확보했는데 패스프레이즈를 몰라 키를 사용할 수 없을 때
- john 설치(apt install john) — Ubuntu/Debian APT 버전에는 ssh2john.py가 누락된 경우가 많아 openwall/john GitHub 소스 clone 필요, 워드리스트 준비

## 🔹 `ssh2john.py` 스크립트 위치

- `ssh2john.py` 는 John the Ripper(줄여서 JtR)에 포함된 여러 "hash conversion" 유틸리티 중 하나입니다.
- 즉, 별도로 apt에서 설치되는 게 아니라 John the Ripper 소스코드 패키지 안에 들어 있습니다.

보통은 다음 경로에 들어 있습니다:

```bash
/opt/john/run/ssh2john.py
```

혹은

```bash
/usr/share/john/ssh2john.py
```

---

## 🔹 설치 방법

### (1) Kali Linux 같은 보안 배포판에서는

기본적으로 설치되어 있거나 apt로 바로 가능합니다:

```bash
sudo apt update
sudo apt install john
```

설치 후 확인:

```bash
locate ssh2john.py
```

### (2) Ubuntu / Debian 일반 환경에서는

APT로 설치하면 `john`만 들어 있고, `ssh2john.py` 같은 스크립트가 누락된 경우가 많습니다.
이럴 때는 GitHub 공식 repo에서 가져와야 합니다:

```bash
git clone https://github.com/openwall/john.git /opt/john
cd /opt/john/run
```

여기 안에 `ssh2john.py`, `rar2john`, `zip2john` 등이 들어 있습니다.

---

## 🔹 사용 예시

```bash
/opt/john/run/ssh2john.py id_rsa > id_rsa_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash.txt
```

---

✅ 정리:

- apt install john → 기본 JtR 설치
- 변환 스크립트(`ssh2john.py`, `rar2john`, `zip2john`)가 없으면 GitHub에서 소스코드 clone 해야 함

---
