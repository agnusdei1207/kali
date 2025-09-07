## 1️⃣ 개요

**Yescrypt**는 현대적인 **비밀번호 기반 키 도출 함수 (Password-Based Key Derivation Function, PBKDF)** 중 하나로, 주로 비밀번호 저장, 인증 시스템, 보안 키 생성에 사용됩니다.

- **목적**: 단순 해시 함수로는 취약한 비밀번호를 **강력하게 보호**
- **영향 받은 알고리즘**: scrypt, bcrypt, PBKDF2
- **주요 개선점**:

  - 메모리 사용량을 증가시켜 **GPU/ASIC 기반 브루트포스 공격에 저항**
  - 병렬화 공격에 대한 저항력 강화
  - 구성 가능한 해시 파라미터로 보안 vs 성능 균형 조정 가능

---

## 2️⃣ 설계 목표

Yescrypt는 다음 목표를 달성하도록 설계되었습니다:

1. **메모리 강제 사용 (Memory-hard)**

   - 공격자가 병렬로 연산할 때 비용을 높임
   - scrypt와 유사하게 메모리 기반 방어

2. **병렬 공격 저항**

   - 다중 CPU/GPU를 이용한 공격 시 효율 감소

3. **유연성**

   - 라운드 수, 메모리 비용, 출력 길이 등 다양한 파라미터 조절 가능

4. **호환성**

   - 기존 shadow 파일 형식과 호환 가능
   - Linux PAM 모듈, crypt() 인터페이스에서 쉽게 통합 가능

---

## 3️⃣ 내부 구조

Yescrypt는 크게 3단계로 구성됩니다:

1. **입력 처리 (Input Encoding)**

   - 비밀번호, salt, 옵션 파라미터 입력
   - 초기 키와 IV(Initialization Vector) 생성

2. **혼합 단계 (Mixing/Memory-hard)**

   - scrypt와 유사한 **ROMix 기반 구조** 사용
   - 메모리 버퍼를 반복적으로 읽고 쓰면서 연산 → 병렬 공격 억제
   - 블록 단위 XOR, SHA-256, Salsa20/ChaCha20 같은 PRF 사용

3. **출력 단계 (Output Derivation)**

   - 최종 키를 지정한 길이만큼 추출
   - Linux /etc/shadow에서는 **기본 256-bit** 해시 출력
   - base64 인코딩 후 shadow 파일에 저장

---

## 4️⃣ 파라미터

Yescrypt는 파라미터를 통해 **보안과 성능을 조절**할 수 있습니다:

| 파라미터 | 설명                                      |
| -------- | ----------------------------------------- |
| `N`      | 메모리 블록 수, 높을수록 메모리 비용 증가 |
| `r`      | 블록 크기, 메모리 접근 패턴 결정          |
| `p`      | 병렬화 정도, 공격자 효율 감소             |
| `t`      | 라운드 수 (CPU 연산 반복)                 |
| `dkLen`  | 최종 출력 길이 (예: 32 bytes = 256 bits)  |

- 예: `/etc/shadow` 저장용 yescrypt: `$y$j9T$...`

  - `$y$` → yescrypt 식별자
  - `j9T` → 옵션 (rounds, memory, parallelism)
  - 나머지 → salt + hash

---

## 5️⃣ 보안 특성

- **메모리 강제 (Memory-hard)** → GPU 공격 비용 증가
- **병렬 공격 저항** → 다중 스레드/GPU 공격 효율 감소
- **Salt 기반** → 동일 비밀번호라도 해시가 달라짐 → rainbow table 방지
- **Configurable** → 필요한 수준에 따라 연산량 및 메모리 증가

---

## 6️⃣ 활용 사례

1. **Linux 시스템**: PAM 모듈을 통한 `/etc/shadow` 암호화
2. **보안 소프트웨어**: 패스워드 저장, 인증 토큰 생성
3. **펜테스트/포렌식**: weak hash 탐지, yescrypt 기반 해시 크래킹 연구

---

## 7️⃣ 요약 (핵심 포인트)

- **Yescrypt = 강화된 scrypt/crypt 기반 PBKDF**
- **메모리 + CPU 비용 조절 가능 → 브루트포스/병렬 공격 저항**
- **기본 해시 길이 256-bit**, shadow 파일에 base64 인코딩 저장
- **Linux PAM, crypt() 인터페이스** 호환 → 실사용 안전성 확보
- **펜테스터/DevSecOps**: yescrypt 해시는 crack 난이도가 높아, weak hash 탐지 및 공격 연구용으로 활용

---
