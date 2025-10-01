import math

def isPrime(n: int) -> bool:
    if n < 2: return False
    small = [2,3,5,7,11,13,17,19,23,29,31,37]
    for p in small:
        if n == p: return True
        if n % p == 0: return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2; s += 1
    for a in small:
        if a % n == 0: continue
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1: break
        else:
            return False
    return True

def next_prime(n: int) -> int:
    n += 1
    while not isPrime(n):
        n += 1
    return n

def first_primes(n: int):
    if n <= 0: return []
    if n <= 5: return [2,3,5,7,11][:n]
    bound = int(n * (math.log(n) + math.log(math.log(n)))) + 8
    while True:
        sieve = bytearray(b"\x01") * (bound + 1)
        sieve[0:2] = b"\x00\x00"
        lim = int(bound ** 0.5)
        for p in range(2, lim + 1):
            if sieve[p]:
                start = p * p
                sieve[start:bound + 1:p] = b"\x00" * (((bound - start)//p) + 1)
        primes = [i for i in range(2, bound + 1) if sieve[i]]
        if len(primes) >= n:
            return primes[:n]
        bound = int(bound * 1.5) + 32

def to_bits(bb: bytes):
    out = []
    for b in bb:
        for k in range(7):
            out.append(1 if (b & (1 << k)) else 0)
    return out

M = b"whenyhwhenyh: CTFITB2025{https://youtu.be/NLphEFOyoqM?si=ST3WMAnGfuKXpzU3}"

bits_m = to_bits(M)

r = 131
n = 7 * len(M)
if r > n:
    raise ValueError("r must be <= n")
primes = first_primes(n)

prod_last_r = 1
for p in primes[n - r:]:
    prod_last_r *= p
q = next_prime(prod_last_r)

acc = 1
for i in range(min(len(primes), len(bits_m))):
    if bits_m[i] == 1:
        acc = (acc * (primes[i] % q)) % q
z = acc

with open("kisah.txt", "w", encoding="utf-8") as out:
    out.write(f"q={q}\n")
    out.write(f"z={z}\n")
