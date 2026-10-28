# decode_ascii (ASCII 코드 → 텍스트)

## 개요

바이트를 ASCII 코드(10진수 32~126)로 출력하고, 다시 해석하는 도구다. 이 문서는 인코딩 관련(common/cryptography)의 간단 정리다.

## 사용법

```bash
# ASCII 코드 문자열로 출력
printf "\143\155\144\n"      # cmd
printf "\160\163\145\162\165\163\145\n"   # process

# 파일의 각 줄을 ASCII 코드로
xxd -ps file.txt
```

## python으로 복호화

```python
data = b'Hello'
print(data.decode('ascii'))      # Hello
print(data.decode('utf-8'))
```

## 실전에서 하는 일

- HTTP 응답의 raw 바이트를 확인할 때 유용하다.
- OSCP 시험에서 쿠키/인코딩 분석에 이 도구가 함께 등장한다(참고: [cookie-decode.md](../../web/cookie-decode.md)).
- 결론적으로 python3/urllib로 디코딩하는 편이 더 일반적이다.

## 참고

- 더 넓은 인코딩 표는 [ENCODING_DECODING_REFERENCE.md](../ENCODING_DECODING_REFERENCE.md)를 따른다.
- 모든 시도는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
- 모든 시도는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.
- 해당 도구의 공식 문서는 --help를 참조하여 추가 옵션을 확인한다.
- 테스트 결과를 스크린샷으로 남겨 증적 자료로 활용한다.
- 유사한 취약점이 다른 머신에도 있는지 확인한다.
