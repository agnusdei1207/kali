권한 상승용 SUID 바이너리나 의심스러운 실행 파일을 분석할 때, 아래와 같은 절차를 따릅니다.

**1. strings 명령어로 바이너리 내부 문자열 확인**

- `strings /usr/sbin/run_container`
- 실행 경로, 쉘 호출, 스크립트 경로 등 힌트가 나옵니다.
- 예시: bash, `/opt/run_container.sh` 등

**2. ldd로 라이브러리 의존성 확인**

- `ldd run_container`
- 어떤 라이브러리를 사용하는지 확인합니다.

**3. file 명령어로 파일 타입 확인**

- `file run_container`
- ELF 바이너리인지, 스크립트인지 확인합니다.

**4. SUID/SGID 권한 확인**

- `ls -l run_container`
- root 권한으로 실행되는지 확인합니다.

**5. 실행 흐름 추측**

- strings 결과에서 `/bin/bash /opt/run_container.sh`가 보이면,  
  해당 스크립트가 root 권한으로 실행될 가능성이 높습니다.

**6. 스크립트 내용 확인**

- `/opt/run_container.sh` 파일을 직접 열어봅니다.
- 취약한 명령어, 환경 변수, 경로 문제, 권한 문제 등을 찾습니다.

**7. 취약점 악용 시도**

- 스크립트 내 명령어 오염, 경로 오염, 환경 변수 오염 등  
  권한 상승이 가능한지 테스트합니다.

**8. 필요시 바이너리 역분석(advanced)**

- OSCP에서는 기본적인 strings, ltrace, strace, gdb 정도까지만 사용합니다.

**정리**

- 바이너리 분석은 strings, ldd, file, 권한 확인, 실행 흐름 파악, 관련 파일 분석 순서로 진행합니다.
- OSCP에서는 자동화 도구 없이 직접 수동으로 분석하는 것이 원칙입니다.
