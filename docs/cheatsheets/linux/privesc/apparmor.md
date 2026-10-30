# apparmor

## 개요

`apparmor`은 Linux에 기본 내장된 접근 제어(Mandatory Access Control)이다. 권한 상승 공격 전에, 특정 바이너리에 제한이 걸려 있는지 확인하면 공격 경로를 더 정확히 잡을 수 있다.

## 확인 방법

```bash
# 현재 적용된 프로파일 목록
sudo apparmor status

# 특정 프로파일 상세
sudo apparmor info /usr/bin/<대상바이너리>
sudo cat /etc/apparmor.d/<대상바이너리>

# 프로파일의 훅(hook) 확인
sudo aa-complain /usr/bin/<대상바이너리>   # 현재 적용을 완화
sudo aa-enforce /usr/bin/<대상바이너리>   # 강화
```

## 실전에서 하는 일

- AppArmor이 특정 바이너리를 강제하면, 해당 바이너리의 SUID 권한 사용이 막힐 수 있다.
- `aa-complain` 상태에서 시도해 보고, 막히면 공격 경로를 다른 계열로 시도한다.
- AppArmor 제약 자체가 취약점이 아니라는 점을 인지하고, 제약이 없는 경로를 먼저 찾는다.

## 참고

- 대부분의 운영체제에서는 AppArmor/SELinux가 기본 활성화되어 있다.
- SELinux는 주로 RHEL 계열이고, Ubuntu/Debian은 AppArmor을 쓴다.
- 두 제약이 걸린 바이너리는 공격성이 줄어들 수 있다. (04-privilege-escalation/linux/privilege_escalation_overview.md 참고)

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
- 해당 도구의 공식 문서는 --help를 참조하여 추가 옵션을 확인한다.
- 테스트 결과를 스크린샷으로 남겨 증적 자료로 활용한다.
- 유사한 취약점이 다른 머신에도 있는지 확인한다.
