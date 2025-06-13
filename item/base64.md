# Base64 인코딩 및 디코딩

OSCP 시험 중 데이터 전송, 저장, 바이너리 파일 처리 등 다양한 상황에서 Base64 인코딩과 디코딩이 필요할 수 있습니다. 특히 웹 취약점 테스트나 바이너리 파일을 텍스트로 전송할 때 유용합니다.

## 기본 설치 정보

Base64는 대부분의 리눅스 배포판(특히 칼리 리눅스)에 기본적으로 설치되어 있습니다. `coreutils` 패키지의 일부로 포함됩니다.

만약 설치되어 있지 않다면:

```bash
# Debian/Ubuntu/Kali
sudo apt-get update
sudo apt-get install coreutils

# CentOS/RHEL/Fedora
sudo yum install coreutils
```

## 명령줄에서 Base64 사용법

### 텍스트 인코딩

```bash
# 기본 텍스트 인코딩
echo -n "OSCP 시험 데이터" | base64
# 결과: T1NDUCA3OO2VnCDrjbDsnbTthLA=

# -n 옵션은 줄바꿈 문자를 제거합니다. 이는 정확한 인코딩을 위해 중요합니다.
```

### 텍스트 디코딩

```bash
# 기본 텍스트 디코딩
echo -n "T1NDUCA3OO2VnCDrjbDsnbTthLA=" | base64 -d
# 결과: OSCP 시험 데이터

# 파일에서 디코딩
base64 -d encoded.txt > decoded.txt
```

### 파일 인코딩

```bash
# 파일 전체를 Base64로 인코딩
base64 binary_file > encoded_file.txt

# 또는 한 줄로 표시 (줄바꿈 없이)
base64 -w 0 binary_file > encoded_file.txt
```

### 파일 디코딩

```bash
# Base64로 인코딩된 파일을 원래 형식으로 디코딩
base64 -d encoded_file.txt > original_file

# 또는 파이프를 통해
cat encoded_file.txt | base64 -d > original_file
```

## 프로그래밍 언어를 이용한 방법

### Python을 이용한 방법

```bash
# 인코딩
python3 -c "import base64; print(base64.b64encode(b'OSCP 시험 데이터').decode())"
# 결과: T1NDUCA3OO2VnCDrjbDsnbTthLA=

# 디코딩
python3 -c "import base64; print(base64.b64decode('T1NDUCA3OO2VnCDrjbDsnbTthLA=').decode())"
# 결과: OSCP 시험 데이터

# 파일 인코딩
python3 -c "import base64, sys; print(base64.b64encode(open(sys.argv[1], 'rb').read()).decode())" filename

# 파일 디코딩
python3 -c "import base64, sys; open(sys.argv[2], 'wb').write(base64.b64decode(open(sys.argv[1]).read()))" encoded.txt decoded_file
```

### Perl을 이용한 방법

```bash
# 인코딩
perl -MMIME::Base64 -e 'print encode_base64("OSCP 시험 데이터")'
# 결과: T1NDUCA3OO2VnCDrjbDsnbTthLA=

# 디코딩
perl -MMIME::Base64 -e 'print decode_base64("T1NDUCA3OO2VnCDrjbDsnbTthLA=")'
# 결과: OSCP 시험 데이터
```

## 실전 활용 사례

### 1. 웹쉘 업로드 우회

웹 응용 프로그램에서 파일 업로드 필터를 우회하기 위해 웹쉘을 Base64 인코딩하여 업로드한 후 서버에서 디코딩하는 방법:

```bash
# 웹쉘 파일 인코딩
base64 -w 0 shell.php > shell_encoded.txt

# 서버에서 디코딩 (업로드 성공 후)
echo '<?php $data = file_get_contents("shell_encoded.txt"); file_put_contents("shell_decoded.php", base64_decode($data)); ?>' > decode_script.php
```

### 2. 데이터 은닉

로그나 트래픽에서 민감한 데이터를 숨기기 위해 Base64 인코딩을 사용할 수 있습니다:

```bash
# 중요 명령어나 스크립트를 Base64로 인코딩
echo -n "cat /etc/passwd" | base64
# 결과: Y2F0IC9ldGMvcGFzc3dk

# 디코딩 및 실행
echo -n "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash
```

### 3. 이진 파일 전송

텍스트 채널을 통해 바이너리 파일을 안전하게 전송:

```bash
# 공격 머신에서
base64 -w 0 payload.exe > payload.b64

# 대상 머신에서
base64 -d payload.b64 > payload.exe
chmod +x payload.exe
```

### 4. 인증 헤더 생성

Basic 인증 헤더 생성:

```bash
# 사용자 이름:비밀번호 형식 인코딩
echo -n "admin:password123" | base64
# 결과: YWRtaW46cGFzc3dvcmQxMjM=

# curl과 함께 사용
curl -H "Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM=" http://target-site.com/
```

### 5. 개인정보 평문 저장 방지

로그나 스크립트에 평문 자격 증명을 저장하지 않기 위해 Base64 인코딩 사용:

```bash
# 암호 인코딩
PASSWORD=$(echo -n "SuperSecretPassword123" | base64)
echo "인코딩된 암호: $PASSWORD"

# 필요할 때 디코딩
DECODED_PASSWORD=$(echo -n "$PASSWORD" | base64 -d)
echo "디코딩된 암호: $DECODED_PASSWORD"
```

## 주의사항

1. Base64는 암호화가 아닌 인코딩 방식입니다. 보안 목적으로 사용하기에는 적합하지 않습니다.
2. Base64로 인코딩된 데이터는 약 33% 정도 크기가 증가합니다.
3. 일부 Base64 구현에서는 패딩 문자('=')가 URL에서 문제를 일으킬 수 있으므로 URL 전송 시 추가 인코딩이 필요할 수 있습니다.
4. OSCP 시험에서 필요한 경우 자격 증명이나 민감한 정보를 저장하는 데 사용할 수 있지만, 실제 상황에서는 더 안전한 방법을 사용해야 합니다.
