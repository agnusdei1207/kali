# rockyou / wordlists

## 개요

해시 크래킹과 무차별 대입(brute force) 시 wordlist가 기본 자료다.
`rockyou.txt`(base64, gzip)와 `SecLists`(공개, 최신)를 함께 사용한다.

## wordlist 설치

```bash
sudo apt update
sudo apt install wordlists -y
sudo apt install seclists -y

# rockyou 압축 해제
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
- 모든 시도는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.

## 참고

- `rockyou`은 구버전 해시에 특화되어 있다. OSCP 시험의 크리덴셜 공격에서는 현재 해시 형식을 우선한다.
- 최신 wordlist는 SecLists의 `Discovery`과 `Credentials` 디렉터리를 확인한다.
