# rockyou / wordlists

- rockyou.txt와 SecLists 워드리스트 활용 정리 — rockyou.txt(gzip 압축 해제 후 /usr/share/wordlists/)를 hashcat·hydra·john의 패스워드 후보군으로, SecLists는 디렉터리·크리덴셜 리스트로 함께 쓰는 방법
- 해시 크래킹이나 브루트포스를 시작하기 전 후보 리스트를 준비할 때, 대입이 오래 걸려 해시 알고리즘에 맞는 리스트를 골라야 할 때
- wordlists·seclists 패키지 설치(apt install)와 rockyou.txt.gz 압축 해제(gzip -d) — rockyou는 구버전 해시에 특화되어 있어 최신 해시 형식은 SecLists Credentials 디렉터리를 우선 확인

## 개요

해시 크래킹과 무차별 대입(brute force) 시 wordlist가 기본 자료다.
`rockyou.txt`(base64, gzip)와 `SecLists`(공개, 최신)를 함께 사용한다.

## wordlist 설치

```bash
sudo apt update
sudo apt install wordlists -y
sudo apt install seclists -y

# rockyou 압축 해제
apt install gzip
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz /usr/share/wordlists/
```

## 주요 디렉터리

```bash
ls /usr/share/wordlists/                  # root
ls /usr/share/wordlists/rockyou.txt      # rockyou
ls /opt/SecLists/Discovery/Web-Content/ # sqlmap 페이로드용
ls /opt/SecLists/Discovery/Credentials/ # 해시 크래킹용
```

## 사용 예시

```bash
hashcat -a 0 -m 0 "844ffc2c7150b93c4133a6ff2e1a2dba" /usr/share/wordlists/rockyou.txt

# Hydra — SSH brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10

# John the Ripper — sha512crypt 해시
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# hashcat — GPU가 있는 경우
hashcat -m 27000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

## 주의

- wordlist는 공용으로 두고, 민감한 경로를 만들지 않는다.
- 대입이 오래 걸리면 wordlist를 고른다. 예: MD5는 md5crypt, sha512는 sha512crypt.

## 참고

- `rockyou`은 구버전 해시에 특화되어 있다. OSCP 시험의 크리덴셜 공격에서는 현재 해시 형식을 우선한다.
- 최신 wordlist는 SecLists의 `Discovery`과 `Credentials` 디렉터리를 확인한다.
