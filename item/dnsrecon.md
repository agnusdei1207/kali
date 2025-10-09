### dnsrecon: Kali Linux에서의 설치부터 사용법까지

dnsrecon은 DNS 재정찰(enumeration) 도구로, 도메인의 DNS 레코드(MX, SOA, NS, A, AAAA, SPF, TXT 등)를 열거하거나 존 트랜스퍼(zone transfer), 브루트포스 서브도메인 등을 수행합니다. Kali Linux에서 보안 테스트나 침투 테스트 시 유용하며, OSCP 같은 시험에서도 허용되는 열거 도구입니다. 아래에서 Kali에서의 설치, 기본 사용법, 옵션별 상세 설명, 실제 명령어 예시를 정리하겠습니다. 정보는 Kali 공식 문서와 GitHub, 커뮤니티 가이드를 기반으로 합니다.

#### 1. 설치 (Installation)

Kali Linux(2023 이후 버전)에는 **기본적으로 설치되어 있습니다**. `dnsrecon --version` 명령으로 확인하세요. 만약 설치되지 않았다면, 아래 명령으로 설치할 수 있습니다.

- **기본 설치 명령**:

  ```
  sudo apt update
  sudo apt install dnsrecon
  ```

  - 설치 후 확인: `dnsrecon -h` (도움말 출력).

- **Python 기반 설치 (선택적, 개발자용)**:
  GitHub에서 직접 클론해 설치할 수 있습니다. Kali의 Python 3.12+ 환경에서 uv 도구를 사용:

  ```
  curl -LsSf https://astral.sh/uv/install.sh | sh
  git clone https://github.com/darkoperator/dnsrecon.git
  cd dnsrecon
  uv sync
  uv run dnsrecon
  ```

  이는 가상 환경을 생성하며, 테스트나 커스터마이징에 유용합니다.

  설치 시간: 1-2분. 의존성: Python 3, dnspython 라이브러리 (자동 설치됨).

#### 2. 기본 사용법 (Basic Usage)

dnsrecon은 명령줄 기반으로 동작하며, 주요 형식은 다음과 같습니다:

```
dnsrecon [옵션] -d <도메인>
```

- `-d <domain>`: 대상 도메인 지정 (필수).
- 출력: 콘솔에 DNS 레코드 목록 출력. 결과를 파일로 저장하려면 `-x <output.xml>` 또는 `-j <output.json>` 사용.
- 도움말: `dnsrecon -h`로 모든 옵션 확인.

예: 기본 스캔

```
dnsrecon -d example.com
```

이 명령은 example.com의 표준 DNS 레코드(A, MX 등)를 열거합니다.

#### 3. 옵션별 상세 설명 (Options)

dnsrecon의 옵션은 DNS 재정찰 시나리오에 따라 다양합니다. 아래 테이블은 주요 옵션을 분류해 정리했습니다. (전체 옵션은 `dnsrecon -h` 참조; 약 20개 이상 있음). 옵션은 문자열, 파일 경로, IP 등 타입에 따라 다릅니다.

| 카테고리           | 옵션            | 설명 (Description)                                                                                                                                                                                                  | 타입 (Type)              | 필수 여부 |
| ------------------ | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ | --------- |
| **기본 대상 지정** | `-d domain`     | 대상 도메인 지정 (e.g., example.com). 모든 작업의 기반.                                                                                                                                                             | 문자열 (string)          | 필수      |
| **테스트 타입**    | `-t type`       | 수행할 테스트 타입 지정. std (표준 열거), axfr (존 트랜스퍼), brt (브루트포스), srv (SRV 레코드), tld (TLD 확장), cache (캐시 확인), ptr (PTR 리버스), rpz (RPZ 확인). 여러 타입 콤마로 결합 가능 (e.g., std,axfr). | 문자열 (comma-separated) | 선택      |
| **브루트포스**     | `-D dict`       | 브루트포스에 사용할 단어 사전 파일 (e.g., /usr/share/wordlists/dnsmap.txt). 서브도메인 추측에 사용.                                                                                                                 | 파일 경로 (file path)    | 선택      |
| **네임서버**       | `-n nameserver` | 지정 NS 서버 사용 (e.g., 8.8.8.8). 기본은 시스템 NS.                                                                                                                                                                | IP/호스트 (IP/host)      | 선택      |
| **범위 지정**      | `-r from-to`    | IP 범위 스캔 (e.g., 192.168.1.1-192.168.1.254). PTR 레코드에 유용.                                                                                                                                                  | IP 범위 (IP range)       | 선택      |
| **출력 형식**      | `-x file.xml`   | 결과를 XML 파일로 저장.                                                                                                                                                                                             | 파일 경로 (file)         | 선택      |
| **출력 형식**      | `-j file.json`  | 결과를 JSON 파일로 저장.                                                                                                                                                                                            | 파일 경로 (file)         | 선택      |
| **고급 열거**      | `-a`            | 모든 DNS 레코드 열거 (A, AAAA, MX, NS, SOA, SPF, TXT). std와 유사하지만 포괄적.                                                                                                                                     | 플래그 (flag)            | 선택      |
| **고급 열거**      | `-s`            | SRV 레코드만 열거 (서비스 발견에 유용, e.g., \_ldap.\_tcp.example.com).                                                                                                                                             | 플래그 (flag)            | 선택      |
| **고급 열거**      | `-w`            | 와일드카드 해상도 확인 (e.g., \*.example.com이 모든 쿼리에 응답하는지 테스트).                                                                                                                                      | 플래그 (flag)            | 선택      |
| **고급 열거**      | `-T timeout`    | 쿼리 타임아웃 설정 (초 단위, 기본 10초). 느린 네트워크에 유용.                                                                                                                                                      | 정수 (integer)           | 선택      |
| **기타**           | `-v`            | 상세(Verbose) 모드: 더 많은 로그 출력.                                                                                                                                                                              | 플래그 (flag)            | 선택      |
| **기타**           | `-f`            | 실패한 쿼리 무시 (e.g., NXDOMAIN 무시하고 계속).                                                                                                                                                                    | 플래그 (flag)            | 선택      |
| **기타**           | `--threads N`   | 멀티스레딩 (기본 1, 최대 50). 브루트포스 속도 향상.                                                                                                                                                                 | 정수 (integer)           | 선택      |
| **기타**           | `-h`            | 도움말 출력.                                                                                                                                                                                                        | 플래그 (flag)            | -         |

- **참고**: `-t` 옵션의 세부 타입:
  - `std`: 표준 레코드 (A, MX 등).
  - `axfr`: 존 트랜스퍼 시도 (NS 서버별 테스트).
  - `brt`: 브루트포스 ( `-D`와 함께 사용).
  - `srv`: SRV 레코드.
  - `tld`: TLD 확장 (e.g., example.com.br).
  - `cache`: 캐시된 DNS 확인.
  - `ptr`: 리버스 DNS (IP to hostname).
  - `rpz`: RPZ (Response Policy Zone) 확인.

#### 4. 실제 사용되는 명령어 예시 (Practical Command Examples)

아래는 재정찰 시나리오별 실제 명령어입니다. Kali의 `/usr/share/wordlists/` 디렉토리에 사전 파일이 많아 활용하세요. 각 예시는 출력 예시와 함께 설명.

1. **기본 DNS 열거 (Standard Enumeration)**:

   ```
   dnsrecon -d example.com -t std
   ```

   - 출력 예: SOA, NS, MX, A 레코드 목록 (e.g., mail.example.com MX 10).
   - 용도: 도메인 기본 구조 파악.

2. **브루트포스 서브도메인 (Brute Force Subdomains)**:

   ```
   dnsrecon -d example.com -t brt -D /usr/share/wordlists/dnsmap.txt --threads 10
   ```

   - 출력 예: www.example.com (A 93.184.216.34), admin.example.com (존재).
   - 용도: 숨겨진 서브도메인 발견. 사전 파일은 5000+ 단어 포함.

3. **존 트랜스퍼 테스트 (Zone Transfer)**:

   ```
   dnsrecon -d example.com -t axfr -n ns1.example.com
   ```

   - 출력 예: 성공 시 전체 존 덤프 (모든 레코드); 실패 시 "Transfer Failed".
   - 용도: NS 서버 취약점 확인.

4. **SRV 레코드 열거 (SRV Records)**:

   ```
   dnsrecon -d example.com -t srv -s
   ```

   - 출력 예: \_sip.\_tcp.example.com SRV 0 1 5060 sipserver.example.com.
   - 용도: 내부 서비스 (LDAP, SIP 등) 발견.

5. **IP 범위 리버스 DNS (Reverse DNS for IP Range)**:

   ```
   dnsrecon -d example.com -t ptr -r 192.168.1.1-192.168.1.100
   ```

   - 출력 예: 192.168.1.10 PTR host10.example.com.
   - 용도: 네트워크 호스트 이름 매핑.

6. **TLD 확장 및 와일드카드 확인 (TLD Expansion & Wildcard)**:

   ```
   dnsrecon -d example -t tld -w
   ```

   - 출력 예: example.co.uk (존재), \*.example.com (와일드카드 응답).
   - 용도: 국제 도메인 변형 탐색.

7. **전체 스캔 + 출력 저장 (Full Scan with Output)**:
   ```
   dnsrecon -d example.com -t std,axfr,brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -x output.xml -v
   ```
   - 출력: XML 파일에 모든 결과 저장 + 콘솔 상세 로그.
   - 용도: 보고서 생성 시.

- **팁**:
  - 느린 네트워크: `-T 20` 추가.
  - 대량 스캔: `--threads 20`로 속도 UP (CPU 부하 주의).
  - 오류 처리: `-f`로 NXDOMAIN 무시.
  - 결과 분석: XML/JSON을 jq나 xmlstarlet으로 파싱.
