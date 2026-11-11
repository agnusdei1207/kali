# which / type

> 무엇: 명령어의 실행 파일 실제 경로를 찾는 which와, 함수·별칭까지 보여주는 type의 사용법을 정리한 문서
> 언제: 권한 상승 확인 단계에서 sudo -l로 허용된 명령이나 bash·sudo·crontab의 실제 위치를 보고, /usr/local/bin처럼 PATH 조작 공격 후보가 되는 경로인지 판단할 때 쓴다
> 조건: 리눅스 기본 도구라 설치가 필요 없으며, 현재 세션의 PATH 환경변수 기준으로 검색하므로 PATH 상태가 결과에 직접 영향을 준다

## 개요

`which`은 명령어의 실제 위치를 찾는 도구다. PATH 변조 후 공격하는 경로를 잡는 데 쓴다.

## 사용법

```bash
which bash
which nc
which python3

# type은 함수/별칭까지 포함해 보여준다
type ls
```

## 권한 상승 시나리오

```bash
# 악용 가능한 파일 위치 파악
which bash
which sudo
which crontab
```

- 경로가 `/usr/local/bin` 아래에 있으면, PATH 조작 공격의 후보다.
- `/etc/sudoers`에 허용된 명령을 확인한다(`sudo -l`).
- 결과가 `/bin`이 아닌 `/usr/local/bin`이면 직접 실행을 시도한다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
- 해당 도구의 공식 문서는 --help를 참조하여 추가 옵션을 확인한다.
- 테스트 결과를 스크린샷으로 남겨 증적 자료로 활용한다.
- 유사한 취약점이 다른 머신에도 있는지 확인한다.
