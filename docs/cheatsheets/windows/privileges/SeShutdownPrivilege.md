> 무엇: 시스템 종료·재부팅을 할 수 있는 특권 SeShutdownPrivilege
> 언제: whoami /priv에서 보여도 단독 권한 상승으로는 이어지지 않아 넘어간다. 다만 utilman 교체처럼 재부팅이 트리거인 공격의 마무리(shutdown /r)로 쓰인다
> 조건: Enabled여야 종료·재부팅이 가능하고, 이 파일 예시의 상태는 Disabled라 그것조차 불가능하다

SeShutdownPrivilege (Disabled)

시스템을 종료하거나 재부팅할 수 있는 권한입니다.

Enabled 상태라 하더라도 권한 상승으로 이어지지는 않고, 서비스 거부(DoS) 공격이나 강제 재부팅 용도로만 쓰입니다. 현재는 Disabled 상태라 이조차 불가능합니다.
