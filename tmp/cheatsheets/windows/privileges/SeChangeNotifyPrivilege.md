- 디렉터리·파일 순회(Traversal) 검사를 우회하는 특권 SeChangeNotifyPrivilege로, 표준 사용자를 포함해 모든 프로세스에 기본 부여되는 정상 권한
- whoami /priv에서 보여도 권한 상승에 쓸 수 없으므로 확인 즉시 넘어가는 무시 목록이다
- 없음 — 모든 계정에 기본 부여돼 항상 보이고, 악용 가능한 권한 상승 시나리오가 없다

SeChangeNotifyPrivilege (Enabled)

디렉토리 및 파일 순회(Traversal) 체크를 우회하는 권한으로, 윈도우즈 기본 계정(Standard User)을 포함해 모든 프로세스에 기본적으로 부여되는 정상적인 권한입니다. 권한 상승에 쓸 수 없습니다.
