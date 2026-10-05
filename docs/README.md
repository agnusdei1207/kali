# 📚 Kali Documentation Hub

보안 연구, 취약점 분석, 그리고 실습 기록을 체계적으로 관리하는 문서 저장소입니다.

---

## 🔍 CVE 실습 롸잇업

### **2026년**

#### CVE-2026-22200: osTicket PDF 파일 읽기
`📁 [completed/red/cve-2026-22200/](./completed/red/cve-2026-22200/README.md)`

**단계별 구성(1.md~6.md):** 공격 표면 조사 및 취약점 진단(1) → 페이로드 생성 및 티켓 생성(2) → 티켓 번호 브루트포스(3) → PDF 데이터 추출(4) → SSH 후속 침투(5) → 근본 원인 분석(6)
**현재 진행:** `ffuf`로 `/osticket/`을 발견하고 게스트 티켓을 생성했다. 티켓 접근과 PDF 추출은 검증 중이다.

---

## 📋 참고 자료 (Reference)

### **Writeup Guide**
`📄 [WRITEUP_GUIDE.md](./WRITEUP_GUIDE.md)`

CTF 또는 실습을 완료한 후 writeup을 작성하는 방법

---

## 📚 치트시트 (Cheatsheets)

`📁 [cheatsheets/](./cheatsheets/)`

### 카테고리별 정리:
- **01-Reconnaissance** - 정보 수집 및 스캔 기법
- **02-Vulnerability Analysis** - 취약점 분석 및 공격
- **03-Initial Access** - 초기 접근 및 쉘 확보
- **04-Privilege Escalation** - 권한 상승
- **05-Lateral Movement** - 횡이동
- **06-Post-Exploitation** - 후처리 및 포렌식
- **common** - 공통 도구 및 기본 명령어

---

## ✅ 완료된 실습 (Completed Labs)

`📁 [completed/red/](./completed/red/README.md)`

풀이 완료된 CTF, THM, HackTheBox, OffSec 등의 writeup 기록 (총 32개 랩 디렉터리별 분류 관리)

---

## 🎯 사용 방법

### 새로운 Writeup 추가

```
1. docs/completed/red/[실습명]/ 폴더 생성
2. docs/WRITEUP_GUIDE.md 참고
3. 단계별 또는 README.md 마크다운 작성
4. docs/completed/red/README.md 인덱스에 추가
```

### 새로운 Cheatsheet 추가

```
1. docs/cheatsheets/[카테고리]/ 폴더 확인
2. 마크다운 형식으로 작성
3. 카테고리별 하위 폴더 생성
4. 파일 저장
```

---

## 📊 폴더 구조

```
kali/
└── docs/
    ├── README.md (이 파일)
    ├── WRITEUP_GUIDE.md
    ├── cheatsheets/
    └── completed/
        └── red/
            ├── README.md (32개 랩 인덱스)
            ├── attacktive-directory/
            ├── cve-2026-22200/
            │   ├── README.md
            │   ├── 1.md
            │   ├── 2.md
            │   ├── 3.md
            │   ├── 4.md
            │   ├── 5.md
            │   ├── 6.md
            │   └── tmp/
            ├── ... (총 32개 실습 디렉터리)
            └── w1se-guy/
```

---

## ✨ 문서 작성 팁

### 1. 가이드 선택
- **CTF/실습 풀이?** → `WRITEUP_GUIDE.md` 사용
- **도구 정보?** → `cheatsheets/` 추가

### 2. 체계성
- 각 섹션은 명확한 목적을 가져야 함
- 단계별 진행 과정을 명확히
- 배운 점은 일반화하기

### 3. 가독성
- 마크다운 형식 준수
- 코드 블록은 언어 명시
- 이모지는 섹션 구분에만 사용

### 4. 연결성
- 관련 문서끼리 링크 연결
- 다른 가이드 참고 시 경로 명시

---

## 🔗 빠른 링크

| 항목 | 경로 |
|---|---|
| CVE-2026-22200 롸잇업 | [completed/red/cve-2026-22200/](./completed/red/cve-2026-22200/README.md) |
| Red Team 실습 허브 | [completed/red/](./completed/red/README.md) |
| Writeup 가이드 | [WRITEUP_GUIDE.md](./WRITEUP_GUIDE.md) |
| 치트시트 | [cheatsheets/](./cheatsheets/) |
| 완료된 실습 인덱스 | [completed/](./completed/README.md) |

---

**마지막 업데이트:** 2026-10-05
