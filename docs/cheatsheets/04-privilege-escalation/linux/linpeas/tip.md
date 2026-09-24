```sh
╔══════════╣ Unexpected in /opt (usually empty)
total 20
drwxr-xr-x 3 root root 4096 Jan 10 2024 .
drwxr-xr-x 18 root root 4096 Nov 9 10:57 ..
drwx--x--x 4 root root 4096 Nov 14 2023 containerd
-rw-r--r-- 1 root root 861 Dec 7 2023 dockerfile
-rwxrwxrwx 1 root root 1715 Jan 10 2024 run_container.sh
```

컨테이너 런(run_container)은 빨간색으로 표시되지 않았지만, SUID/SGID가 붙어 있고, 사용자 추가 파일로 분류되어 있습니다.  
린피스에서 빨간색은 "거의 확실한 권한 상승 벡터"를 의미하지만, 빨간색이 아니더라도 SUID/SGID가 붙은 사용자 추가 바이너리는 항상 직접 분석 대상입니다.

빨간색이 아니더라도 다음 이유로 주목해야 합니다.

- SUID/SGID가 붙은 바이너리는 root 권한으로 실행됨
- 시스템 기본이 아닌, 사용자가 추가한 실행 파일은 취약점이 있을 확률이 높음
- 린피스가 "Unknown SUID binary!"로 표시한 것은 자동 진단이 안 됐다는 뜻이므로, 직접 분석해야 함

즉, 빨간색이 아니더라도 SUID/SGID가 붙은 사용자 추가 파일(run_container, run_container.sh 등)은 항상 직접 실행해보고, 취약점(명령어 인젝션, 경로 오염, 환경 변수 오염 등)이 있는지 확인해야 합니다.

**정리:**  
빨간색이 아니어도 SUID/SGID 사용자 추가 파일은 무조건 분석 대상입니다.  
자동화 툴이 취약점 여부를 100% 판단하지 못하므로, 직접 확인하는 것이 중요합니다.
