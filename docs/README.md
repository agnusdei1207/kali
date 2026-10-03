# 📚 Kali Documentation Hub

보안 연구, 취약점 분석, 그리고 실습 기록을 체계적으로 관리하는 문서 저장소입니다.

---

## 📖 가이드 (Guides)

### 1. **인사이트 문서 작성법**
`📄 [guides/insight-documentation-guide.md](./guides/insight-documentation-guide.md)`

**어떻게 쓸까?**
- 기술 연구/취약점 분석을 효과적으로 문서화하는 방법
- 연구 과정의 시행착오를 명확하게 전달
- 일반화된 배움(인사이트)을 도출하는 방법

**포함 내용:**
- 기본 구조 템플릿
- 5가지 작성 원칙
- 체크리스트
- 좋은 예시 vs 나쁜 예시

**언제 사용?**
- 새로운 취약점을 발견했을 때
- 기술 연구를 문서화할 때
- 다른 사람들과 배운 점을 공유할 때

---

## 🔍 CVE 분석 (CVE Analysis)

### **2026년**

#### CVE-2026-22200: osTicket "Ticket to Shell"
`📄 [cve/2026/cve-2026-22200-insight.md](./cve/2026/cve-2026-22200-insight.md)`

**핵심:**
- osTicket의 파일 읽기 취약점
- HTML 정제 계층 우회 기법
- 단일 우회 vs 다층 공략의 차이

**주요 인사이트:**
- 보안 계층은 개별 우회가 아닌 "층층 공략" 필요
- 인코딩은 정제의 맹점 (공백, 엔티티 활용)
- 복잡한 파이프라인 = 더 많은 부채

**구성:**
1. 핵심 요약 (1문단)
2. 연구 배경
3. 5단계 연구 과정 (문제 → 원인 → 해결)
4. 최종 솔루션
5. 5가지 핵심 인사이트
6. 실제 코드 예시
7. 검증 방법

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

### 새로운 취약점 분석 추가

```
1. docs/cve/[연도]/ 폴더 확인
2. guides/insight-documentation-guide.md 참고
3. 문서 작성 (템플릿 사용)
4. 체크리스트 완료 확인
5. 파일 저장
```

### 새로운 Writeup 추가

```
1. docs/completed/[카테고리]/ 폴더 생성
2. WRITEUP_GUIDE.md 참고
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
docs/
├── README.md (이 파일)
├── WRITEUP_GUIDE.md
│
├── guides/
│   └── insight-documentation-guide.md
│       └── 취약점 분석을 체계적으로 작성하는 방법
│
├── cve/
│   ├── 2026/
│   │   └── cve-2026-22200-insight.md
│   │       └── osTicket 파일 읽기 취약점 분석
│   ├── 2025/
│   ├── 2024/
│   └── ...
│
├── cheatsheets/
│   ├── 01-reconnaissance/
│   ├── 02-vulnerability-analysis/
│   ├── 03-initial-access/
│   ├── 04-privilege-escalation/
│   ├── 05-lateral-movement/
│   ├── 06-post-exploitation/
│   └── common/
│
└── completed/
    ├── red/
    │   ├── Attacktive Directory.md
    │   ├── billing.md
    │   └── ...
    └── ...
```

---

## ✨ 문서 작성 팁

### 1. 가이드 선택
- **취약점 분석?** → `guides/insight-documentation-guide.md` 사용
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
| 인사이트 작성법 | [guides/insight-documentation-guide.md](./guides/insight-documentation-guide.md) |
| CVE 분석 | [cve/2026/](./cve/2026/) |
| Writeup 가이드 | [WRITEUP_GUIDE.md](./WRITEUP_GUIDE.md) |
| 치트시트 | [cheatsheets/](./cheatsheets/) |
| 완료된 실습 | [completed/](./completed/) |

---

**마지막 업데이트:** 2026-10-03
