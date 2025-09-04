**Diffie-Hellman 키 교환(DH, Diffie-Hellman key exchange)**

주어진 값:

- $p = 29$ (소수, 모듈러 연산의 기준)
- $g = 5$ (생성기, generator)
- $b = 17$ (비밀 키)

DH에서 공개키 $B$는 **다음 공식**으로 계산합니다:

$$
B \equiv g^b \mod p
$$

즉:

$$
B \equiv 5^{17} \mod 29
$$

---

### 1. 지수 나누어서 계산 (제곱과 곱셈 방법)

효율적으로 계산하기 위해 \*\*제곱과 곱셈 방법(Exponentiation by Squaring)\*\*을 쓰겠습니다.

1. $5^1 \equiv 5 \mod 29$
2. $5^2 \equiv 5 \cdot 5 = 25 \mod 29$
3. $5^4 \equiv 25^2 = 625 \equiv ? \mod 29$

계산:

$$
625 ÷ 29 = 21 \text{ 나머지 } 16
$$

→ $5^4 \equiv 16 \mod 29$

4. $5^8 \equiv 16^2 = 256 \mod 29$

$$
256 ÷ 29 = 8 × 29 = 232, 나머지 24
$$

→ $5^8 \equiv 24 \mod 29$

5. $5^{16} \equiv 24^2 = 576 \mod 29$

$$
576 ÷ 29 = 19 × 29 = 551, 나머지 25
$$

→ $5^{16} \equiv 25 \mod 29$

---

### 2. 최종 계산 $5^{17}$

$$
5^{17} = 5^{16} \cdot 5^1 \equiv 25 \cdot 5 = 125 \mod 29
$$

$$
125 ÷ 29 = 4 × 29 = 116, 나머지 9
$$

✅ 따라서 $B \equiv 9 \mod 29$

---

**결론:**

$$
\boxed{B = 9}
$$
