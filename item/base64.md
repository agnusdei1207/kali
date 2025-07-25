# base64 - 인코딩/디코딩

## 주요 옵션

- `-d`, `--decode` : 디코딩 모드
- `-i`, `--ignore-garbage` : 디코딩 시 base64 문자가 아닌 것 무시
- `-w`, `--wrap=COLS` : COLS 바이트마다 줄바꿈 (기본 76, 0은 줄바꿈 없음)
  -n : echo 명령어에서 사용, 마지막 개행 문자 제거 (base64 인코딩/디코딩 시 오류 방지)

## 기본 명령어

### 텍스트 변환

```bash
# 텍스트 → base64
echo -n "admin:password" | base64     # YWRtaW46cGFzc3dvcmQ=
# echo -n : 마지막 개행 문자 제거 (base64 인코딩/디코딩 시 오류 방지)


# base64 → 텍스트
echo -n "YOUR_STRING_HERE" | tr -d '\n\r ' | base64 -d
echo -n "YWRtaW46cGFzc3dvcmQ=" | base64 -d  # admin:password
# echo -n : 마지막 개행 문자 제거, tr -d '\n\r ' : 불필요한 개행/공백 제거
```

### 파일 처리

```bash
# 파일 → base64 (줄바꿈 포함)
base64 shell.php > shell.b64

# 파일 → base64 (한 줄로)
base64 -w 0 shell.php > shell.b64

# base64 → 파일
base64 -d shell.b64 > shell.php
cat shell.b64 | base64 -d > shell.php
```

# 깨지는 경우 파이썬으로

### Python

```bash
# 인코딩
python3 -c "import base64; print(base64.b64encode(b'비밀번호').decode())"

# 디코딩
python3 -c "import base64; print(base64.b64decode('67Cx66Gd67KI7Zi4').decode())"

# 파일 인코딩
python3 -c "import base64, sys; print(base64.b64encode(open(sys.argv[1], 'rb').read()).decode())" shell.php
```

### 원라이너

```bash
# 명령어 인코딩 후 실행
echo -n "cat /etc/passwd" | base64     # Y2F0IC9ldGMvcGFzc3dk
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash     # 원격지에서 실행
```

## 침투 활용

### 파일 전송

```bash
# 공격자 → 대상 서버
base64 -w 0 shell.php > shell.txt     # 로컬에서 인코딩
# shell.txt 내용을 복사하여 타겟 서버에 붙여넣기
base64 -d > shell.php << 'EOF'        # 타겟에서 실행
[붙여넣은 내용]
EOF
```

### 웹쉘 우회

```bash
# 기본 디코딩 웹쉘 템플릿
<?php
$data = '디코딩할문자열';
file_put_contents('shell.php', base64_decode($data));
?>

# 파일로 저장
echo "<?php
\$data = '디코딩할문자열';
file_put_contents('shell.php', base64_decode(\$data));
?>" > decode.php

# 실행
php decode.php
```

### Basic 인증

```bash
# Basic 인증 헤더 생성
echo -n "admin:password" | base64     # YWRtaW46cGFzc3dvcmQ=
curl -H "Authorization: Basic YWRtaW46cGFzc3dvcmQ=" https://target.com/
```
