#### 1. 설치 (Kali Linux)

Kali Linux(2023.4 이상)에서 기본 설치되어 있음. 확인: `dnsrecon --version`. 없으면 아래 명령어로 설치:

```bash
sudo apt update
sudo apt install dnsrecon -y
```

- 확인: `dnsrecon -h` (도움말).
- 의존성: `python3`, `python3-dnspython` (자동 설치).
- 설치 시간: ~30초.

#### 2. 주요 옵션 (간략)

- `-d <domain>`: 대상 도메인 (필수).
- `-t <type>`: 테스트 타입 (std, axfr, brt, srv, tld, ptr, cache, rpz).
- `-D <dict>`: 브루트포스 사전 파일 (e.g., `/usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt`).
- `-n <nameserver>`: NS 서버 (e.g., 8.8.8.8).
- `-r <from-to>`: IP 범위 (e.g., 192.168.1.1-192.168.1.100).
- `-x <file.xml>`: XML 출력.
- `-j <file.json>`: JSON 출력.
- `-v`: 상세 출력.
- `--threads N`: 멀티스레드 (최대 50).
- `-f`: 실패 쿼리 무시.

#### 3. 자주 사용되는 명령어

OSCP 및 실전 중심, 간결한 예시:

1. **기본 DNS 열거**:

   ```bash:disable-run
   dnsrecon -d example.com -t std
   ```

   - 용도: A, MX, NS, SOA 등 기본 레코드 확인.

2. **서브도메인 브루트포스**:

   ```bash
   dnsrecon -d example.com -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt --threads 10
   ```

   - 용도: 숨겨진 서브도메인 (admin, dev 등) 탐색.

3. **존 트랜스퍼 테스트**:

   ```bash
   dnsrecon -d example.com -t axfr
   ```

   - 용도: 취약한 DNS 서버 점검.

4. **SRV 레코드 열거**:

   ```bash
   dnsrecon -d example.com -t srv
   ```

   - 용도: LDAP, SIP 등 서비스 발견.

5. **리버스 DNS 조회**:

   ```bash
   dnsrecon -d example.com -t ptr -r 192.168.1.1-192.168.1.100
   ```

   - 용도: IP별 호스트 이름 매핑.

6. **TLD 확장 확인**:

   ```bash
   dnsrecon -d example -t tld
   ```

   - 용도: .com, .co.uk 등 변형 도메인 탐색.

7. **전체 스캔 + 출력 저장**:
   ```bash
   dnsrecon -d example.com -t std,axfr,brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -x output.xml
   ```
   - 용도: 보고서용 데이터 저장.

#### 4. 팁

- **빠른 스캔**: `--threads 20`, `-f` 추가.
- **Seclists**: `/usr/share/seclists/Discovery/DNS/`의 사전 파일 사용.
- **OSCP**: 존 트랜스퍼(`axfr`) 성공 시 플래그 가능성 높음.
- **대안**: `dig`, `host`, `nmap --script dns-brute`.

```

```
