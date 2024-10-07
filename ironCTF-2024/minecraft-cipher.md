### Minecraft cipher

```
My friend alice has been playing minecraft for long time and made me this
challenge. Can you solve this?

image.py
flag.enc
```

We're given a LCG with parameters a,b and starting state x. At each step,
the state is changed via `x -> a*x+b`, and the LCG outputs bits 9 to 23:

```python
import random

class CustomRandom:
    def __init__(self, m=2**64):
        self.m = m
        self.a = random.getrandbits(64)
        self.b = random.getrandbits(64)
        self.x = random.getrandbits(64)
        print(f"{self.x = }")  # self.x = 9014855307380235246

    def next_bytes(self):
        self.x = (self.a*self.x + self.b) % self.m
        return int(bin(self.x)[-16:-9],2),int(bin(self.x)[-23:-16],2)
```

The bytes of this stream are then XORed with the bytes of a PNG image to get
an encrypted image, which we are given as `flag.enc`.

We're also given the starting value of x, but not the values of a and b.

### Solution

First, note that only the last 23 bits of a, b, and x matter. We can perform
all the operations in mod 2^23, because the LCG only outputs bits of the lower
23 bits.

Second, a PNG image always has the header `x89\x50\x4E\x47\x0D\x0A\x1A\x0A`, so
we can XOR it with the first 8 bytes of the encrypted file to get the first 8
bytes of the LCG stream: `66, 62, 100, 126, 47, 67, 85, 81`.

The first 8 bytes come from the state values
`a*x+b, a(a*x+b)+b, a(a(a*x+b)+b)+b, a(a(a(a*x+b)+b)+b)+b`.
So the goal is to find a, b (mod 2^23) such that bits 9-16 and bits 16-23 of
these state values match the expected bytes. So we have
```
ax+b              ≡  66 * 2^9 +  62 * 2^16 + ɛ₁ (mod 2^23)
a(ax+b)           ≡ 100 * 2^9 + 126 * 2^16 + ɛ₂ (mod 2^23)
a(a(ax+b))+b      ≡  47 * 2^9 +  67 * 2^16 + ɛ₃ (mod 2^23)
a(a(a(ax+b))+b)+b ≡  85 * 2^9 +  81 * 2^16 + ɛ₄ (mod 2^23)
```
for some `0 ≤ ɛ₁, ɛ₂, ɛ₃, ɛ₄ < 2^9`.

There are 2^46 pairs of numbers (a, b), so we can't just try each pair to see
if it satisfies the above 4 conditions. However, we can build the correct pair
incrementally by computing the possible values of (a, b) mod 2, then mod 4, then
mod 8, etc. If we know the possible values of (a, b) mod 2^n, then the only
possible values mod 2^{n+1} are (a, b), (a, b+2^n), (a+2^n, b), (a+2^n, b+2^n),
and we can filter down to only the values that satisfy the conditions mod 2^{n+1}.

```python
from pwn import *

x = 9014855307380235246

png_header = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'
im = open("flag.enc", 'rb').read()
stream_bytes = xor(png_header, im)  # [66, 62, 100, 126, 47, 67, 85, 81]

# start with: the only possible value of (a, b) mod 1 is (0, 0)
mod = 1
valid_params = [(0, 0)]
while mod < 2 ** 23:
    new_valid_params = []
    for low_a, low_b in valid_params:
        # try (a, b), (a, b+2^n), (a+2^n, b), (a+2^n, b+2^n)
        for high_a in range(2):
            for high_b in range(2):
                a = high_a * mod + low_a
                b = high_b * mod + low_b

                # check if this new (a, b) works mod 2^{n+1}
                good = True
                x = 9014855307380235246
                for i in range(4):
                    x = (a * x + b) % (2 * mod)
                    if (x
                        - (stream_bytes[2 * i] << 9)
                        - (stream_bytes[2 * i + 1] << 16)) % (2 * mod) >= 2 ** 9:
                        good = False
                if good:
                    new_valid_params.append((a, b))
    mod *= 2
    valid_params = new_valid_params
a, b = valid_params[0]  # 2442001, 8249463
```

The resulting (a, b) can be used to decrypt the image. The flag is
```
ironCTF{1cG_W!Th_Some_BruTeFORc3_actioN}
```
