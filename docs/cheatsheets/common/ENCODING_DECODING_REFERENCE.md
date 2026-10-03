# 인코딩/디코딩 전체 참고서

데이터를 다양한 형식으로 변환하는 인코딩/디코딩 방법을 한곳에서 정리합니다.

## 빠른 참고

| 형식 | 용도 | 복호화 여부 | 상세 |
|------|------|-----------|------|
| Base64 | 텍스트/바이너리 전송 | ✅ 복호화 가능 | [base64.md](../cryptography/base64.md) |
| URL Encoding | URL 안전 전송 | ✅ 복호화 가능 | [url_encode_decode.md](../scripts/url_encode_decode.md) |
| ASCII | 문자 코드 변환 | ✅ 변환 가능 | [ascii.md](../cryptography/ascii.md) |
| Hex (16진수) | 바이너리 표현 | ✅ 변환 가능 | 아래 참고 |
| ROT13 | 간단한 문자 치환 | ✅ 복호화 가능 | 아래 참고 |
| HTML Entity | 웹 문자 인코딩 | ✅ 복호화 가능 | 아래 참고 |

## 1. Base64

텍스트, 바이너리, 이미지를 텍스트 형식으로 변환합니다.

### 인코딩
```bash
# 문자열 Base64 인코딩
echo "Hello World" | base64

# 파일 Base64 인코딩
base64 myfile.txt

# URL 안전 Base64 (+ 대신 -, / 대신 _)
echo "Hello World" | base64 | tr '+/' '-_'
```

### 디코딩
```bash
# Base64 문자열 디코딩
echo "SGVsbG8gV29ybGQ=" | base64 -d

# 파일 디코딩
base64 -d encoded.txt > original.txt

# 여러 줄 Base64 디코딩
cat encoded.txt | base64 -d
```

자세한 내용: [base64.md](../cryptography/base64.md)

---

## 2. URL 인코딩/디코딩

URL이나 폼 데이터에서 안전한 문자 전송

### 인코딩

특수문자를 %16진수로 변환

```bash
# Python으로 인코딩
python3 -c "import urllib.parse; print(urllib.parse.quote('Hello World & Special'))"
# 결과: Hello%20World%20%26%20Special

# Bash로 인코딩
echo "Hello World" | sed 's/ /%20/g'
```

### 디코딩

%16진수를 다시 문자로 변환

```bash
# Python으로 디코딩
python3 -c "import urllib.parse; print(urllib.parse.unquote('Hello%20World%20%26%20Special'))"
# 결과: Hello World & Special

# 온라인 또는 jq 사용
echo "Hello%20World" | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))"
```

일반 문자: 그대로 (A-Z a-z 0-9 - _ . ~)
특수문자: %16진수 (예: 공백=%20, &=%26, #=%23)

자세한 내용: [url_encode_decode.md](../scripts/url_encode_decode.md)

---

## 3. ASCII / 문자 코드

문자를 숫자 코드로 변환

### ASCII 값 보기

```bash
# 문자의 ASCII 값 확인
echo "A" | od -An -tdC
# 결과: 65

# 모든 문자의 ASCII 값
python3 -c "print([ord(c) for c in 'Hello'])"
# 결과: [72, 101, 108, 108, 111]
```

### ASCII 값으로 문자 변환

```bash
# 숫자를 문자로
python3 -c "print(chr(65))"
# 결과: A

# 여러 ASCII 값
python3 -c "print(''.join(chr(c) for c in [72, 101, 108, 108, 111]))"
# 결과: Hello
```

자세한 내용: [ascii.md](../cryptography/ascii.md)

---

## 4. Hex (16진수)

바이너리 데이터를 읽기 좋은 16진수로 표현

### 문자 → Hex

```bash
# echo + xxd
echo -n "Hello" | xxd -p
# 결과: 48656c6c6f

# Python
python3 -c "print('Hello'.encode().hex())"
# 결과: 48656c6c6f

# od 사용
echo -n "Hello" | od -An -tx1
# 결과: 48 65 6c 6c 6f
```

### Hex → 문자

```bash
# xxd로 복원
echo "48656c6c6f" | xxd -r -p
# 결과: Hello

# Python
python3 -c "print(bytes.fromhex('48656c6c6f').decode())"
# 결과: Hello
```

### 파일 Hex 보기

```bash
# 파일 Hex 덤프
hexdump -C myfile.txt

# xxd로 보기
xxd myfile.txt
```

자세한 내용: [ascii.md](../cryptography/ascii.md)

---

## 5. ROT13

각 문자를 13칸 뒤로 밀기 (A→N, B→O 등)

### 인코딩/디코딩

```bash
# ROT13 변환 (같은 명령으로 인코딩, 디코딩 모두 가능)
echo "Hello World" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# 결과: Uryyb Jbeyq

# 다시 실행하면 원래대로
echo "Uryyb Jbeyq" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# 결과: Hello World

# Python
python3 -c "print(__import__('codecs').encode('Hello World', 'rot_13'))"
# 또는
python3 -c "import codecs; print(codecs.encode('Hello World', 'rot13'))"
```

특징: 대칭 암호화 (인코딩과 디코딩이 같은 연산)

---

## 6. HTML Entity

웹에서 특수문자 표현

### 일반 Entity

```bash
# HTML entity 인코딩
python3 << 'EOF'
import html
text = '<div>Hello & "World"</div>'
print(html.escape(text))
# 결과: &lt;div&gt;Hello &amp; &quot;World&quot;&lt;/div&gt;
EOF

# 문자별 Entity
# < → &lt;
# > → &gt;
# & → &amp;
# " → &quot;
# ' → &#39;
```

### HTML Entity 디코딩

```bash
# Python
python3 << 'EOF'
import html
text = '&lt;div&gt;Hello &amp; &quot;World&quot;&lt;/div&gt;'
print(html.unescape(text))
# 결과: <div>Hello & "World"</div>
EOF

# 온라인에서 &#로 시작하는 숫자 entity
# &#65; → A (ASCII 65)
# &#x41; → A (16진수)
```

---

## 7. 숫자 인코딩

### 2진수 (Binary)

```bash
# 문자 → 2진수
python3 -c "print(bin(ord('A')))"
# 결과: 0b1000001

# 2진수 → 문자
python3 -c "print(chr(int('1000001', 2)))"
# 결과: A
```

### 8진수 (Octal)

```bash
# 문자 → 8진수
python3 -c "print(oct(ord('A')))"
# 결과: 0o101

# 8진수 → 문자
python3 -c "print(chr(int('101', 8)))"
# 결과: A
```

---

## 8. 암호화 해시

### MD5 (복호화 불가)

```bash
# 문자열 MD5
echo -n "Hello" | md5sum
# 결과: 8b1a9953c4611296aaf7a3c316de3453

# 파일 MD5
md5sum myfile.txt
```

### SHA (복호화 불가)

```bash
# SHA1
echo -n "Hello" | sha1sum

# SHA256
echo -n "Hello" | sha256sum

# SHA512
echo -n "Hello" | sha512sum
```

해시는 복호화 불가능 (일방향)
같은 입력 = 같은 해시

자세한 내용: [hashid.md](../cryptography/hashid.md), [md5sum.md](../cryptography/md5sum.md)

---

## 빠른 변환 명령어

### 문자 → 다양한 형식

```bash
TEXT="Hello"

# Base64
echo -n "$TEXT" | base64

# URL
python3 -c "import urllib.parse; print(urllib.parse.quote('$TEXT'))"

# Hex
echo -n "$TEXT" | xxd -p

# ASCII 값들
python3 -c "print([ord(c) for c in '$TEXT'])"

# ROT13
echo "$TEXT" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

### 역변환 (복호화)

```bash
# Base64 복호화
echo "SGVsbG8=" | base64 -d

# URL 디코딩
python3 -c "import urllib.parse; print(urllib.parse.unquote('Hello'))"

# Hex 복원
echo "48656c6c6f" | xxd -r -p

# ROT13 역변환 (자기 자신)
echo "Uryyb" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

---

## 도구별 선택 가이드

### 온라인 변환
- cyberchef.io: 여러 형식 한번에
- base64decode.org: Base64 전문
- urlencoder.io: URL 인코딩 전문

### CLI 도구

```bash
# Python (가장 유연함)
python3 -c "..."

# echo + 파이프
echo "text" | base64

# 전문 도구
xxd (Hex)
md5sum, sha256sum (Hash)
tr (ROT13)
```

### 스크립트 작성

```bash
#!/bin/bash
input="$1"
format="$2"

case "$format" in
  base64) echo -n "$input" | base64 ;;
  url) python3 -c "import urllib.parse; print(urllib.parse.quote('$input'))" ;;
  hex) echo -n "$input" | xxd -p ;;
  rot13) echo "$input" | tr 'A-Za-z' 'N-ZA-Mn-za-m' ;;
esac
```

---

## 관련 파일들

디렉토리별로 정리된 상세 가이드:

인코딩/해시:
- [base64.md](../cryptography/base64.md)
- [ascii.md](../cryptography/ascii.md)
- [decode_ascii.md](../cryptography/decode_ascii.md)
- [hashid.md](../cryptography/hashid.md)
- [md5sum.md](../cryptography/md5sum.md)

스크립트 유틸:
- [url_encode_decode.md](../scripts/url_encode_decode.md)
- [javascript_url_encode.md](../scripts/javascript_url_encode.md)

---

## 팁

- Base64는 인코딩이지 암호화가 아님 (복호화 누구나 가능)
- 해시(MD5, SHA)는 일방향 (복호화 불가)
- URL 인코딩은 URL 안전 문자만 남김
- ROT13은 보안용이 아닌 난독화용
- 파일 크기 확인: Base64는 약 33% 커짐

---

마지막 업데이트: 2026-10-03
