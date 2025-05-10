<div align="center">
    <img src="https://www.kali.org/images/kali-dragon-icon.svg" alt="Kali Linux 로고" width="150" />
</div>

### Docker 기반 Kali Linux 보안 & 침투 테스트 활동을 위해 격리된 환경을 제공합니다.

# 침투 방법론

# 1. 정보 수집

    - 포트스캔 (wireshark)
    - nc 직접 연결 스캔
    - 서비스 스캔
    - exploit framework

# 2. 취약점

    - DDOS | DOS 는 스트레스 테스트에 주로 사용하며 실제 모의해킹에서는 자주 사용하지 않음
    - Authenticated, Unauthenticated 인증 또는 미인증 payload 공격이 가능한지 판단하기
    - SSH 공개키 확보
    - 힙메모리, 어셈블리 침투 등 복잡한 방법도 많지만 고급보다는 쉬운 방법의 조합으로도 얼마든지 대문열고 들어갈 수 있음
    - 서비스, OS, 하드웨어 등 다양한 방식으로 수집한 취약점들을 조합하여 공격 계획 세우기
    - 수동 (정확도, 디테일, 비용) / 자동 (거짓 양성, 거짓 음성) 취약점 진단
    	1. 오픈된 포트가 있는가
    	2. 어떤 서비스를 사용중인가
    	3. 연결이 되는가
    	4. 소통이 되는가
    	5. 어떤 정보를 수집할 수 있는가
    	6. 수집한 정보를 조합하여 취약점을 찾아내고 해당 취약점을 악용할 수 있는 방법은 무엇인가

# 3. 초반 분석

    - source 분석 웹이라면 OWASP REST API
    - sink 입력된 값에 대해 시스템과 서비스 내에서 어떻게 사용되는가

## 웹

    - burpsuite (postman + webproxy)
