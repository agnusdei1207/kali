# Sublist3r

- Sublist3r — Google·Bing·VirusTotal 등 검색엔진과 SSL 인증서 데이터를 긁어 서브도메인을 모아 주는 열거 도구. -b로 DNS 브루트포스도 병행한다.
- DNS 정찰 초기에 서브도메인 목록을 뽑아 nmap·httprobe 같은 후속 스캔 대상 파일을 만들 때.
- apt/pip 설치와 requests·dnspython 의존성이 필요하고, 결과는 -o로 파일 저장해야 손실이 없으며 스레드는 -t 20-50이 적당하다.

### Kali Linux

```bash
apt update && apt install sublist3r
sublist3r -h
```

### Manual Installation

```bash
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
pip install -r requirements.txt
python sublist3r.py -h
```

### 설치 확인

```bash
which sublist3r
sublist3r --version
```

## Basic Usage

### 기본 실행

```bash
sublist3r -d target.com
python sublist3r.py -d example.com
```

### 결과 파일 저장

```bash
sublist3r -d target.com -o subdomains.txt
python sublist3r.py -d example.com -o results.txt
```

## Advanced Options

### 특정 검색엔진 사용

```bash
sublist3r -d target.com -e google,yahoo,bing
sublist3r -d target.com -e virustotal,dnsdumpster
```

### 브루트포스 활성화

```bash
sublist3r -d target.com -b
sublist3r -d target.com -b -t 100
```

### 커스텀 워드리스트

```bash
sublist3r -d target.com -b -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### 스레드 수 조정

```bash
sublist3r -d target.com -t 50
```

### Verbose 출력

```bash
sublist3r -d target.com -v -o results.txt
```

## Search Engines

```
baidu, yahoo, google, bing, ask, netcraft,
virustotal, threatcrowd, ssl, dnsdumpster
```

## Real-world Examples

### CTF/Lab 환경

```bash
sublist3r -d tryhackme.com -b -t 100 -o thm_subdomains.txt
sublist3r -d hackthebox.eu -e google,virustotal,dnsdumpster -o htb_subs.txt
```

### 종합 스캔

```bash
sublist3r -d target.com -b -e google,yahoo,bing,virustotal -t 50 -o complete_scan.txt
```

## Tool Integration

### httprobe와 연계

```bash
sublist3r -d target.com -o subs.txt && cat subs.txt | httprobe
```

### nmap과 연계

```bash
sublist3r -d target.com -o subs.txt && nmap -iL subs.txt -p 80,443
```

### 결과 카운트

```bash
sublist3r -d target.com | tee subs.txt | wc -l
```

## Troubleshooting

### 의존성 설치

```bash
pip install requests dnspython argparse
pip install --upgrade requests
python3 -m pip install -r requirements.txt
```

### 일반적인 에러

- ModuleNotFoundError: `pip install missing_module`
- SSL errors: `pip install --upgrade certifi`
- DNS timeout: `-t` 파라미터로 스레드 수 줄이기

## Performance Tips

- 스레드 수: `-t 20-50` (속도/안정성 균형)
- 수동 열거 먼저, 브루트포스는 나중에
- 'all' 대신 특정 엔진 사용
- 결과 손실 방지를 위해 파일 저장 필수
