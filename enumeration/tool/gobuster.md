# Gobuster

Gobuster는 디렉토리, DNS, vhost 등을 브루트포스하는 도구로, Go 언어로 작성되어 빠른 스캐닝을 제공합니다. 웹 사이트의 숨겨진 디렉토리, 파일, 하위 도메인 발견에 매우 유용합니다.

## 설치 방법

Kali Linux에는 기본적으로 설치되어 있지만, 없는 경우 다음 명령어로 설치할 수 있습니다:

```bash
sudo apt update
sudo apt install gobuster -y
```

소스코드에서 직접 설치하려면:

```bash
sudo apt install golang -y
go install github.com/OJ/gobuster/v3@latest
```

## 주요 모드

Gobuster는 세 가지 주요 모드를 제공합니다:

1. **dir** - 웹 사이트의 디렉토리/파일 브루트포싱
2. **dns** - 하위 도메인 브루트포싱
3. **vhost** - 가상 호스트 브루트포싱

## 기본 사용법

### 디렉토리 및 파일 스캔 (dir 모드)

```bash
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
```

### 하위 도메인 스캔 (dns 모드)

```bash
gobuster dns -d target.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

### 가상 호스트 스캔 (vhost 모드)

```bash
gobuster vhost -u http://target.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

## 고급 옵션 및 팁

### 디렉토리 스캔 (dir 모드) 주요 옵션

| 옵션                         | 설명                                |
| ---------------------------- | ----------------------------------- |
| -u, --url                    | 타겟 URL                            |
| -w, --wordlist               | 워드리스트 경로                     |
| -t, --threads                | 스레드 수 (기본값: 10)              |
| -s, --status-codes           | 찾고자 하는 상태 코드 (예: 200,301) |
| -b, --status-codes-blacklist | 제외할 상태 코드 (예: 404,403)      |
| -e, --expanded               | 전체 URL 출력                       |
| -x, --extensions             | 확장자 지정 (예: php,html,txt)      |
| -k, --no-tls-validation      | TLS 인증서 검증 무시                |
| --wildcard                   | 와일드카드 응답 무시                |
| -a, --user-agent             | 사용자 에이전트 설정                |
| -c, --cookies                | 쿠키 설정                           |
| -o, --output                 | 결과 저장 파일                      |
| -r, --follow-redirect        | 리다이렉트 따라가기                 |

### 실전 스캔 예시

#### 1. 특정 확장자 파일 찾기

```bash
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak
```

#### 2. 특정 상태 코드만 표시

```bash
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -s 200,301,302
```

#### 3. 스레드 수 증가로 스캔 속도 향상

```bash
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -t 50
```

#### 4. 인증이 필요한 사이트 스캔

```bash
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -U username -P password
```

#### 5. 사용자 에이전트 지정

```bash
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

#### 6. 파일 확장자 지정 및 결과 저장

```bash
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x php,html -o gobuster_results.txt
```

## 워드리스트 추천

Gobuster에 사용할 수 있는 좋은 워드리스트:

1. **디렉토리/파일 스캔용**:

   - `/usr/share/wordlists/dirb/common.txt`
   - `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
   - `/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt`
   - `/usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt`
   - `/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt`

2. **하위 도메인 스캔용**:
   - `/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt`
   - `/usr/share/wordlists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt`

## 실전 팁

1. **와일드카드 감지**: 서버가 모든 요청에 동일한 응답을 보내는 경우, `--wildcard` 옵션을 사용하여 오탐을 줄일 수 있습니다.

2. **속도 조절**: 방화벽이나 WAF 우회를 위해 `-t` 옵션으로 스레드 수를 낮추고 `-d` (delay) 옵션으로 요청 간 지연을 추가합니다.

3. **콘텐츠 길이에 기반한 필터링**: `-l` 옵션을 사용하여 특정 컨텐츠 길이의 응답을 필터링할 수 있습니다.

4. **다양한 워드리스트 사용**: 여러 워드리스트를 시도하여 발견 확률을 높입니다.

5. **파일 확장자 스캔**: 웹서버 유형을 파악한 후 적절한 파일 확장자를 지정합니다 (예: Apache - php, IIS - asp/aspx).

6. **상태 코드 확인**: 403 Forbidden 응답이 나오는 디렉토리는 액세스 제어가 설정되어 있으므로 추가 조사가 필요할 수 있습니다.

7. **결과 저장 및 분석**: `-o` 옵션을 사용하여 결과를 저장하고, `grep`이나 다른 도구로 추가 분석합니다.

## 실전 시나리오

### 시나리오 1: 웹 애플리케이션 초기 스캔

1. 기본 디렉토리 스캔:

```bash
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -o initial_scan.txt
```

2. 발견된 디렉토리 추가 스캔:

```bash
gobuster dir -u http://target.com/admin -w /usr/share/wordlists/dirb/common.txt -x php -o admin_dir_scan.txt
```

### 시나리오 2: CMS 스캔

WordPress 사이트 스캔:

```bash
gobuster dir -u http://target.com -w /usr/share/wordlists/SecLists/Discovery/Web-Content/CMS/wordpress.txt
```

### 시나리오 3: 백업 파일 탐색

```bash
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x bak,old,backup,txt,conf,cfg -o backup_search.txt
```

## OSCP 시험을 위한 추가 팁

1. **시간 관리**: 큰 워드리스트 대신 common.txt와 같은 작고 효율적인 리스트로 시작하고 필요에 따라 더 큰 리스트로 확장하세요.

2. **병렬 작업**: 스캔이 진행되는 동안 다른 침투 테스트 작업을 수행하여 시간을 효율적으로 활용하세요.

3. **작은 발견도 중요**: 사소해 보이는 디렉토리나 파일이라도 권한 상승이나 추가 접근 경로가 될 수 있습니다.

4. **결과 문서화**: 모든 스캔 결과를 문서화하여 보고서 작성 시 참조하세요.

5. **결합 기법**: Gobuster의 결과를 Nmap, Nikto 등 다른 도구의 결과와 결합하여 전체적인 공격 표면을 이해하세요.

## 주의사항

1. **스레드 수 주의**: 높은 스레드 설정은 대상 서버에 과부하를 줄 수 있습니다.

2. **법적 제한**: 스캔 전에 항상 권한을 확보하고 합법적인 범위 내에서 작업하세요.

3. **시간 관리**: OSCP 시험에서는 효율적인 시간 관리가 중요합니다. 큰 워드리스트보다 작고 정확한 워드리스트를 사용하는 것이 효과적일 수 있습니다.

4. **오탐 주의**: 와일드카드 대응이나 기본 404 페이지가 커스텀되어 있는 사이트에서는 결과 검증이 필요합니다.

5. **다른 도구와 병행**: Gobuster 외에도 dirbuster, ffuf, wfuzz 등 다른 도구를 병행하여 사용하면 더 많은 결과를 얻을 수 있습니다.
