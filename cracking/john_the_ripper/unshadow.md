## 1. 해시 종류 확인

```bash
# 해시값 보기
cat hash1.txt

# 글자 수로 판별
MD5    : 32 hex
SHA1   : 40 hex
SHA256 : 64 hex
NTLM   : John에서 --format=NT
```

---

## 2. NTLM 해시 크랙

```bash
john --format=NT ~/John-the-Ripper-The-Basics/Task05/ntlm.txt
```

---

## 3. /etc/passwd + /etc/shadow 합치기 (unshadow)

```bash
unshadow /etc/passwd /etc/shadow > myhashes.txt
```

### 예시

- `/etc/passwd`

  ```
  alice:x:1000:1000:/home/alice:/bin/bash
  ```

- `/etc/shadow`

  ```
  alice:$6$6N5tH7xy$3OrcHwTR...
  ```

- 결과 (`myhashes.txt`)

  ```
  alice:$6$6N5tH7xy$3OrcHwTR...:1000:1000:/home/alice:/bin/bash
  ```

---

## 4. 크랙 실행

```bash
# 기본 크랙
john myhashes.txt

# 워드리스트 사용 (예: rockyou.txt)
john --wordlist=/usr/share/wordlists/rockyou.txt myhashes.txt

# 크랙된 결과 보기
john --show myhashes.txt
```

---
