---
title: "리포트 작성 (Report Writing)"
date: 2026-06-20
weight: 190
draft: false
tags: ["oscp", "cheatsheet"]
summary: "시험 종료 후 24시간 안에 제출하는 리포트의 구조와 증거 정리 방법."
---

시험 종료 후 24시간 안에 리포트를 제출한다. 리포트가 없으면 100점이라도 통과가 없다.

- 출처: https://heretek.dev/oscp-cheatsheet/report-writing/ (Jean Romero) — 재구성

## 리포트 형식 요건 (Report Format Requirements)

- PDF만 허용 — .7z 파일로 아카이브 (암호 없음, 최대 200MB)
- 파일명: `OSCP-OS-XXXXX-Exam-Report.pdf` (대소문자 구분, XXXXX = OS-ID)
- 업로드처: upload.offsec.com
- 모든 스크립트·PoC 코드는 PDF 본문에 텍스트로 삽입 (외부 파일 불가) ← 중요
- 리포트에 배치한 머신 순서 = 채점 순서

## 리포트 구조 — 템플릿 그대로 (Report Structure)

### 1. 표지 (Cover Page)

- 이름, OS-ID, 시험 날짜

### 2. Executive Summary (1문단)

- 범위, 시간, 사용한 방법론 요약
- 핵심 발견: 획득한 머신 수, 전반적 보안 상태

### 3. 머신별 섹션 (Per-Machine Sections) — 머신마다 반복

3개 standalone + AD 세트, 각 머신마다 아래 항목을 전부 문서화:

```text
Machine: [IP Address]
OS: [Windows/Linux]
Service Enumeration:
  - nmap results (screenshot + key findings)

Initial Access:
  - Vulnerability identified
  - Steps to exploit (numbered, with screenshots)
  - PoC code/commands used
  - Screenshot: proof of shell (whoami output)

Privilege Escalation:
  - Vulnerability identified
  - Steps to exploit (numbered, with screenshots)
  - PoC code/commands used
  - Screenshot: proof.txt with whoami + hostname + ip/ipconfig

Proof:
  - local.txt: [flag value]
  - proof.txt: [flag value]
```

### 4. AD 세트 섹션 (AD Set Section)

- 3대 머신 전체의 공격 체인을 문서화
- 머신 간 lateral movement 표시
- 각 creds를 어디서 얻고 어디에 썼는지 보여주는 creds 표 포함

## proof 스크린샷 요건 — 필수 (Proof Screenshot Requirements)

네 가지 출력이 전부 한 터미널 스크린샷에 보여야 한다:

```bash
# Linux
whoami && hostname && ip a && cat /root/proof.txt

# Windows
whoami && hostname && ipconfig && type C:\Users\Administrator\Desktop\proof.txt
```

스크린샷 필수 요소: 플래그 내용 + whoami + hostname + 네트워크 정보 — 같은 창에 전부. 하나라도 빠지면 그 머신은 0점 ← 중요

## 시험 당일 기록 워크플로우 (Documentation-As-You-Go)

```bash
# Start terminal logging at exam begin
script -a ~/oscp/exam_log_$(date +%F).txt

# For EACH machine, before you start:
mkdir -p ~/oscp/machine_IP
echo "=== STARTING machine_IP $(date) ===" >> ~/oscp/notes.md

# Take screenshots of:
# 1. Every nmap scan result
# 2. Every vulnerability found
# 3. Every exploit command + output
# 4. Every shell obtained (whoami)
# 5. Every proof flag (the 4-in-1 screenshot)
# 6. Every credential found
```

스크린샷은 Flameshot 사용: `flameshot gui`

## 머신별 노트 구조 (Note-Taking Structure Per Machine)

머신마다 같은 구조로 노트. 리포트 작성 때 그대로 옮긴다.

```text
## Machine [IP]

### Enumeration
- Open ports: 22, 80, 445
- Web server: Apache 2.4.49 (vuln to CVE-2021-41773)
- SMB: anonymous access allowed

### Initial Access
- Vulnerability: CVE-2021-41773 Path Traversal RCE
- Command: curl 'http://IP/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh' -d 'echo Content-Type: text/plain; echo; whoami'
- Got shell as: www-data
- Screenshot: [filename.png]

### Privilege Escalation
- Found SUID /usr/bin/find
- Command: find / -exec /bin/bash -p \; -quit
- Got shell as: root
- Screenshot: [filename.png]

### Proof
- local.txt: abc123def456
- proof.txt: 789ghi012jkl

### Credentials Found
- admin:password123 (from /var/www/config.php)
- Sprayed against: [list machines tested]
```

## 흔한 리포트 실수 — 즉시 탈락 (Common Report Mistakes)

- proof 스크린샷 누락 (whoami+hostname+ip+플래그가 한 장에 있어야 한다)
- PDF/7z 파일명 규칙 위반
- 24시간 마감 후 제출
- 공격을 재현할 정도의 세부사항 부족
- 맥락 없는 스크린샷 (무엇을 보여주는지 설명 없음)
- 한 스크린샷에 여러 개념 담기 — 스크린샷 하나당 개념 하나
- 실패한 시도 미포함 (방법론을 보여주는 요소)

## 리포트 작성 타임라인 — 24시간 (Report Writing Timeline)

- 0–1시간: 머신별 스크린샷·노트 정리
- 1–2시간: AD 세트 섹션 작성 (가장 복잡)
- 2–3시간: Standalone 1 섹션 작성
- 3–4시간: Standalone 2 섹션 작성
- 4–5시간: Standalone 3 섹션 + Executive Summary
- 5–6시간: 검토, 교정, PDF 내보내기, 7z 생성, 업로드

## 도구 (Tools)

```bash
# OffSec report template
# Download from: https://www.offensive-security.com/pwk-online/OSCP-Exam-Report.docx

# Generate PDF from markdown (if using Obsidian/markdown)
pandoc report.md -o report.pdf --pdf-engine=xelatex

# Create 7z archive
7z a OSCP-OS-XXXXX-Exam-Report.7z OSCP-OS-XXXXX-Exam-Report.pdf

# Flameshot for screenshots
flameshot gui
```

## 빠른 참조 링크 (같은 폴더 문서)

- 시험 전략 → [exam-strategy.md](exam-strategy.md)
- 전체 흐름 체크리스트 → [methodology.md](methodology.md)
