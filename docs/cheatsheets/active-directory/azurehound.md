# AzureHound

- AzureHound — Azure/Entra ID(M365) 환경을 BloodHound용 JSON으로 수집하는 Go 도구. Entra 역할·구독·리소스 관계를 그래프로 분석하게 해주며, 온프렘 AD의 SharpHound에 대응하는 클라우드 쪽 수집기다.
- 하이브리드·클라우드 환경에서 Entra 권한 관계와 온프렘 동기화 계정을 분석할 때, BloodHound(CE·Legacy)에 Azure 데이터를 먹일 때, M365 테넌트 전체를 한 번에 수집할 때.
- azurehound 바이너리(Go), Entra 계정 또는 az cli 토큰, 분석용 BloodHound.

## 테넌트 데이터 수집 (v2)

```bash
azurehound list -u "$USERNAME" -p "$PASSWORD" -t "$TENANT" -o output.json
azurehound list -t "$TENANT" -o output.json        # 자격증명 프롬프트에서 입력
```

- `-t`: 테넌트 ID·도메인. `-u -p`: Entra 계정. `-o`: 결과 파일.
- 범위를 좁히려면 list 뒤에 개체 종류를 붙인다: azurehound list users / roles / groups / apps / subscriptions 등.

## az cli 토큰 재사용

```bash
az login
JWT=$(az account get-access-token --resource https://graph.microsoft.com | jq -r .accessToken)
azurehound list --jwt "$JWT" -o output.json
```

- `-j/--jwt`: 이미 얻은 액세스 토큰으로 인증. `-r/--refresh-token`: 리프레시 토큰 인증.

## BloodHound Enterprise 수집기 모드

```bash
azurehound configure     # 프롬프트에 따라 수집 서비스 설정 저장
azurehound start         # 수집 시작
```

## BloodHound로 분석

- output.json을 BloodHound에 업로드하면 AzUser·AzRole·AzApp 같은 Azure 노드와 온프렘 User 사이 관계가 그려진다.
- 하이브리드라면 SharpHound·bloodhound-python 수집 결과와 함께 올려 온프렘↔클라우드 경로를 한 화면에서 본다.

## 팁·트러블슈팅

- 토큰 만료·조건부 액세스로 실패하면 az login을 다시 하고 JWT를 재발급한다.
- 계정 권한이 부족하면 일부 개체가 누락된다. Global Reader 같은 읽기 권한 계정이 수집에 유리하다.
- 원인 파악은 --verbosity로, graph.microsoft.com 접근이 방화벽에 막히면 수집 자체가 실패한다.
- 레거시(v1) 워크스루의 `azurehound -u -p list --tenant ...` 형태는 v2(list 서브커맨드 우선)와 다르다. 버전을 먼저 확인.
- 수집 결과는 민감한 권한 관계 데이터다. 파일 관리에 주의한다.
