# Metasploit Framework 설치 가이드

## Kali Linux에서 설치

### 기본 설치 (권장)

```bash
# 시스템 업데이트
sudo apt update && sudo apt upgrade -y

# Metasploit Framework 설치
sudo apt install metasploit-framework -y

# PostgreSQL 설치 (데이터베이스 필요)
sudo apt install postgresql postgresql-contrib -y

# PostgreSQL 서비스 시작
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

### 수동 설치 (최신 버전)

```bash
# 의존성 패키지 설치
sudo apt install curl wget gnupg2 software-properties-common -y

# Rapid7 GPG 키 추가
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | sudo bash

# 또는 GitHub에서 직접 설치
cd /opt
sudo git clone https://github.com/rapid7/metasploit-framework.git
cd metasploit-framework
sudo gem install bundler
sudo bundle install
```

## 데이터베이스 설정

### PostgreSQL 초기 설정

```bash
# PostgreSQL 서비스 확인
sudo systemctl status postgresql

# 사용자 생성 및 권한 설정
sudo -u postgres createuser msf -P
# 패스워드 입력 (예: msf123)

sudo -u postgres createdb -O msf msf_database
```

### Metasploit 데이터베이스 연결

```bash
# msfconsole 실행
msfconsole

# 데이터베이스 연결 (msfconsole 내에서)
db_connect postgresql://msf:msf123@localhost/msf_database

# 또는 설정 파일로 자동 연결
echo "production:
  adapter: postgresql
  database: msf_database
  username: msf
  password: msf123
  host: 127.0.0.1
  port: 5432
  pool: 75
  timeout: 5" > ~/.msf4/database.yml
```

## Ubuntu/Debian 계열 설치

### 저장소 추가 방식

```bash
# 저장소 키 추가
curl https://apt.metasploit.com/metasploit-framework.gpg.key | sudo apt-key add -

# 저장소 추가
echo "deb https://apt.metasploit.com/ lucid main" | sudo tee -a /etc/apt/sources.list.d/metasploit.list

# 업데이트 및 설치
sudo apt update
sudo apt install metasploit-framework -y
```

## macOS 설치

### Homebrew 사용

```bash
# Homebrew 설치 (없는 경우)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Metasploit 설치
brew install metasploit

# PostgreSQL 설치
brew install postgresql
brew services start postgresql

# 데이터베이스 생성
createdb msf_database
```

## Windows 설치

### 공식 인스톨러 사용

1. https://www.metasploit.com/download 접속
2. Windows 버전 다운로드
3. 관리자 권한으로 설치 실행
4. PostgreSQL 자동 설치 옵션 선택

### WSL2 사용 (권장)

```bash
# WSL2에서 Ubuntu 설치 후
sudo apt update
sudo apt install metasploit-framework postgresql -y
```

## 설치 확인

### 기본 실행 테스트

```bash
# 버전 확인
msfconsole --version

# 콘솔 실행
msfconsole

# 데이터베이스 상태 확인 (msfconsole 내)
db_status

# 모듈 수 확인
show exploits | wc -l
show payloads | wc -l
```

## 업데이트

### Kali Linux

```bash
# 시스템 업데이트와 함께
sudo apt update && sudo apt upgrade

# Metasploit만 업데이트
sudo apt update && sudo apt install --only-upgrade metasploit-framework
```

### 수동 설치 업데이트

```bash
cd /opt/metasploit-framework
sudo git pull
sudo bundle install
```

## 문제 해결

### 자주 발생하는 오류들

#### PostgreSQL 연결 오류

```bash
# PostgreSQL 재시작
sudo systemctl restart postgresql

# 사용자 권한 확인
sudo -u postgres psql -c "\du"

# 데이터베이스 재생성
sudo -u postgres dropdb msf_database
sudo -u postgres createdb -O msf msf_database
```

#### 권한 오류

```bash
# MSF 폴더 권한 수정
sudo chown -R $USER:$USER ~/.msf4/
sudo chmod -R 755 ~/.msf4/
```

#### 모듈 로딩 오류

```bash
# 캐시 재생성
msfconsole -x "reload_all; exit"

# 또는 캐시 삭제 후 재시작
rm -rf ~/.msf4/store/
msfconsole
```

## 성능 최적화

### 메모리 설정

```bash
# 환경변수 설정 (~/.bashrc 또는 ~/.zshrc에 추가)
export MSF_DATABASE_CONFIG=~/.msf4/database.yml
export METASPLOIT_FRAMEWORK_ROOT=/usr/share/metasploit-framework
```

### SSD 최적화

```bash
# 임시 파일 위치 변경
export TMPDIR=/tmp/msf
mkdir -p $TMPDIR
```

## 보안 고려사항

### 방화벽 설정

```bash
# 필요한 포트만 허용
sudo ufw allow 4444/tcp  # 기본 리버스 쉘 포트
sudo ufw allow 8080/tcp  # 웹 서버 포트
```

### 로그 관리

```bash
# 로그 디렉토리 확인
ls -la ~/.msf4/logs/

# 로그 정리 스크립트
find ~/.msf4/logs/ -name "*.log" -mtime +30 -delete
```
