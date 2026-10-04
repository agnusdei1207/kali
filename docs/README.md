# 📚 Kali Documentation Hub

보안 연구, 취약점 분석, 그리고 실습 기록을 체계적으로 관리하는 문서 저장소입니다.

---

## 🔍 CVE 실습 롸잇업

### **2026년**

#### CVE-2026-22200: osTicket PDF 파일 읽기
`📄 [cve-2026-22200-writeup.md](../cve-2026-22200-writeup.md)`

**현재 진행:** `ffuf`로 `/osticket/`을 발견하고 게스트 티켓을 생성했다. 티켓 접근과 PDF 추출은 아직 검증 중이다.

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

`📁 [completed/](./completed/)`

풀이 완료된 CTF, THM, HackTheBox 등의 writeup 기록

---

## 🎯 사용 방법

### 새로운 Writeup 추가

```
1. 저장할 경로 선택
2. docs/WRITEUP_GUIDE.md 참고
3. 문서 작성
4. 파일 저장
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
├── cve-2026-22200-writeup.md  # 진행 중인 osTicket 실습 롸잇업
└── docs/
    ├── README.md (이 파일)
    ├── WRITEUP_GUIDE.md
    ├── cheatsheets/
    └── completed/
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
|------|------|
| CVE-2026-22200 롸잇업 | [cve-2026-22200-writeup.md](../cve-2026-22200-writeup.md) |
| Writeup 가이드 | [WRITEUP_GUIDE.md](./WRITEUP_GUIDE.md) |
| 치트시트 | [cheatsheets/](./cheatsheets/) |
| 완료된 실습 | [completed/](./completed/) |

---

**마지막 업데이트:** 2026-10-03
