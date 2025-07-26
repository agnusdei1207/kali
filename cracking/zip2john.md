# zip2john 설치 및 사용법

## 1. zip2john 이란?

- John the Ripper(암호 크래킹 도구)에서 ZIP 압축 파일 암호 해시를 추출하는 툴
- ZIP 파일 암호 크래킹 준비용

---

## 2. 설치 방법 (Ubuntu/Debian 기준)

```bash
sudo apt update
sudo apt install john
```

- `zip2john`은 `john` 패키지에 포함되어 있음
- 설치 후 바로 사용 가능

---

## 3. 사용법

### 기본 사용법

```bash
zip2john 파일명.zip > hash.txt
```

- ZIP 파일의 암호화 정보(해시)를 추출해 `hash.txt`에 저장
- 추출된 해시를 John the Ripper로 크래킹 가능

---

### 예시

```bash
zip2john wordpress.old.zip > wordpress_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt wordpress_hash.txt
```

- 먼저 `zip2john`으로 해시 추출
- 이후 `john`으로 단어 리스트(rockyou.txt) 기반 크래킹

---

## 4. 참고

- `zip2john`은 ZIP 파일에 암호가 걸렸을 때만 유용함
- 암호가 없으면 그냥 unzip으로 풀면 됨

---
