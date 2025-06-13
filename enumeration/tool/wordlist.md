# 워드리스트 다운로드 방법 - 칼리 리눅스

칼리 리눅스에서 사용할 수 있는 여러 워드리스트 다운로드 방법을 소개합니다.

## 1. SecLists (가장 추천)

SecLists는 다양한 보안 평가에 사용되는 여러 유형의 워드리스트를 포함하는 가장 포괄적인 컬렉션입니다.

```bash
# 설치 방법 1: apt를 통한 설치
sudo apt update
sudo apt install seclists

# 설치 경로: /usr/share/seclists/

# 설치 방법 2: git을 통한 직접 다운로드 (최신 버전)
git clone https://github.com/danielmiessler/SecLists.git
```

## 2. 칼리 리눅스 내장 워드리스트

칼리 리눅스에는 기본적으로 다양한 워드리스트가 포함되어 있습니다.

```bash
# 기본 위치
ls /usr/share/wordlists/

# 일반적으로 많이 사용되는 디렉토리
ls /usr/share/wordlists/dirb/
ls /usr/share/wordlists/dirbuster/
ls /usr/share/wordlists/wfuzz/
```

## 3. rockyou.txt (매우 인기 있는 패스워드 워드리스트)

```bash
# rockyou.txt는 기본적으로 압축된 상태로 제공됩니다
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# 압축 해제 후 사용
cat /usr/share/wordlists/rockyou.txt | head
```

## 4. 추가 워드리스트 소스

```bash
# 1. CeWL - 웹사이트에서 커스텀 워드리스트 생성
# 설치
sudo apt install cewl

# 사용 예시 (웹사이트에서 워드리스트 생성)
cewl -d 2 -m 5 -w custom_wordlist.txt http://target-website.com

# 2. Crunch - 패턴 기반 워드리스트 생성
sudo apt install crunch

# 사용 예시 (8-10자리 숫자로만 구성된 워드리스트)
crunch 8 10 0123456789 -o number_wordlist.txt
```

## 워드리스트 비교 및 추천

1. **최신성**: SecLists가 GitHub를 통해 지속적으로 업데이트되어 가장 최신 상태를 유지합니다.
2. **다양성**: SecLists는 다양한 유형의 공격(디렉토리 브루트포싱, 패스워드 크래킹 등)에 맞춘 워드리스트를 포함합니다.
3. **OSCP 관련**: 대부분의 OSCP 실습에는 내장된 워드리스트와 SecLists가 충분합니다.

## 추천 워드리스트 (OSCP 준비용)

1. 디렉토리/파일 브루트포싱: `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt`
2. 패스워드 크래킹: `/usr/share/wordlists/rockyou.txt`
3. 유저네임: `/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt`

OSCP 시험에서는 무차별 대입 공격보다 다른 취약점을 먼저 확인하는 것이 중요하며, 브루트포스는 마지막 수단으로 활용하는 것이 좋습니다.
