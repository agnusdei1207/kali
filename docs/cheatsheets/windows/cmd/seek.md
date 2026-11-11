# 자동화 명령어 탐색

> 무엇: schtasks /query /fo LIST /v로 예약 작업 전체를 상세(LIST/V)로 나열해 자동 실행되는 명령어·경로를 찾아내는 명령
> 언제: 권한 상승 벡터 탐색 단계에서 높은 권한 계정이 실행하는 예약 작업이 취약한 경로·파일을 참조하는지 확인할 때
> 조건: Windows 셸 필요, 출력이 매우 길어 findstr 등으로 필터링해서 보는 편이 낫다

schtasks /query /fo LIST /v
