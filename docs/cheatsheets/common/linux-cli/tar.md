# Tar Command

`tar` (Tape Archive)는 여러 개의 파일을 하나의 아카이브 파일로 묶거나, 압축을 할 때 사용하는 리눅스/유닉스용 표준 도구입니다.

## 설치

대부분의 리눅스 배포판에는 기본으로 설치되어 있습니다. 만약 없다면 아래 명령어로 설치합니다.

```bash
# Debian / Ubuntu / Kali
sudo apt update && sudo apt install tar -y

# RHEL / CentOS / Fedora
sudo dnf install tar -y
```

## 기본 사용법 (C-X-V-F)

주로 사용하는 옵션 4가지만 기억하면 쉽습니다.

*   `-c` (Create): 새로운 아카이브 **생성**
*   `-x` (eXtract): 아카이브 **해제** (풀기)
*   `-v` (Verbose): 과정 **상세 보기**
*   `-f` (File): 대상 **파일명 지정** (항상 마지막에 옵니다)

---

## 주요 예제

### 1. 파일 묶기 (압축 안 함)
여러 파일을 하나로 묶기만 합니다. (확장자 `.tar`)
```bash
tar -cvf archive.tar file1 file2 folder/
```

### 2. 파일 풀기
```bash
tar -xvf archive.tar
```

### 3. gzip으로 압축하며 묶기 (`-z`)
가장 많이 사용하는 방식입니다. (확장자 `.tar.gz` 또는 `.tgz`)
```bash
tar -zcvf archive.tar.gz folder/
```

### 4. gzip 압축 풀기
```bash
tar -zxvf archive.tar.gz
```

### 5. 특정 디렉토리에 풀기 (`-C`)
```bash
tar -xvf archive.tar -C /path/to/directory
```

---

## [중요] 보안 취약점: Wildcard (*) 인젝션

`tar` 명령어 사용 시 와일드카드(`*`)를 사용하면, 파일 이름을 인자로 착각하는 취약점이 발생할 수 있습니다.

**위험한 명령어 예시:**
```bash
tar cf backup.tgz *
```

**취약점 원리:**
파일 이름이 `--checkpoint=1` 혹은 `--checkpoint-action=exec=sh shell.sh`인 파일이 현재 디렉토리에 있다면, `tar`는 이를 파일명이 아닌 **자신의 실행 옵션**으로 인식하여 `shell.sh`를 실행해 버립니다.

**방어 방법:**
와일드카드 대신 구체적인 경로를 지정하거나, `--`를 사용하여 옵션의 끝을 명시합니다.
```bash
tar cf backup.tgz ./*
```
