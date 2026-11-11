# BloodHound (블러드하운드) - AD 권한 관계 시각화

> 무엇: Active Directory의 사용자·그룹·ACL·세션 관계를 neo4j 그래프 DB에 수집해 권한 상승 경로를 시각화하는 도구다.
> 언제: 유효한 도메인 계정을 하나 확보한 뒤, bloodhound-python으로 -c all 수집해 json을 GUI에 업로드하고 Domain Admin까지의 경로·관리 계정·ACL을 읽어낼 때 쓴다.
> 조건: 공격자에 bloodhound와 neo4j 설치·실행이 필요하고(웹 UI http://localhost:7474, 기본 neo4j/neo4j, 최초 로그인 시 비밀번호 변경), 수집은 low priv 계정으로도 가능하나 대상의 RDP·SMB·WinRM 등 관련 포트가 열려 있어야 한다.

설치

```
apt install bloodhound
```

## 네오4j(neo4j) 설치 및 실행

```
apt update
apt install neo4j
```

## 네오4j 서비스 시작/중지/상태

```
systemctl start neo4j
systemctl stop neo4j
systemctl status neo4j
```

## 네오4j 콘솔 직접 실행 (로그 확인용)

```
neo4j console
```

## 웹: http://localhost:7474 (기본 ID: neo4j / PW: neo4j)

## 최초 로그인 시 비밀번호 변경 필요

## BloodHound 실행

```
bloodhound
```

## GUI 실행됨. neo4j에 로그인

## 주요 옵션

- -u : 도메인 계정
- -p : 패스워드
- -d : 도메인명
- -dc : 도메인컨트롤러 IP
- -c all : 모든 정보 수집

## 데이터 수집 (공격대상에서)

```
bloodhound-python -u '사용자' -p '패스워드' -d '도메인' -dc '도메인컨트롤러IP' -c all
```

## 예시

```
bloodhound-python -u 'test' -p '1234' -d 'spookysec.local' -dc 10.10.233.27 -c all
```

## 결과: \*.json 파일 생성됨

## 수집 데이터 업로드

BloodHound GUI → Upload Data → json 파일 업로드

## 실전 팁

- low priv 계정만 있어도 쓸 수 있음
- RDP, SMB, WinRM 등 포트 열려있어야 함
- 결과에서 권한 상승 경로, 관리 권한 계정, ACL 등 확인

## 진짜 자주 쓰는 명령어만 정리함.
