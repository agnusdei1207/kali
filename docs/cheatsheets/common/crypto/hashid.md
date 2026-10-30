# hashid

## 개요

해시 문자열의 알고리즘을 자동으로 판별하는 도구다. 해시cat/john의 `-m`(모듈) 선택을 할 때, 혼자 판별하는 데 유용하다.

## 사용법

```bash
sudo apt install hashid -y

# 해시 파일이나 인자로 들어온 문자열을 판별
hashid hash.txt
hashid "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
```

## 결과 예시

```
Hash: MD5
Decoding: first 32 bits of the MD5 hash
```

## 실전에서 하는 일

- 크리덴셜이 여러 형식으로 섞여 있을 때, hashid으로 우선 알고리즘을 정한다.
- 이후 hashcat/john의 모듈 번호(`-m`)를 지정한다.
- 자주 쓰는 명령만 익히면 충분하며, 상세 옵션은 `hashid -h`로 확인한다.

## 참고

- hashcat 모듈 번호는 문서의 모듈 ID를 참고한다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
- 해당 도구의 공식 문서는 --help를 참조하여 추가 옵션을 확인한다.
- 테스트 결과를 스크린샷으로 남겨 증적 자료로 활용한다.
- 유사한 취약점이 다른 머신에도 있는지 확인한다.
