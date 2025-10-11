from Crypto.Util.number import getPrime, bytes_to_long
import random

with open('flag.txt', 'rb') as f:
    flag = f.read().strip()

lower = 2**399
upper = 2**400

p = getPrime(512)
q = getPrime(512)
n = p * q

e = 65537

pt = bytes_to_long(flag)
assert pt < n

ct = pow(pt, e, n)

mods = []
mods.append(n)
for _ in range(5):
    mods.append(p * getPrime(512) + random.randrange(lower, upper))

with open('output.txt', 'w') as f:
    f.write(f"N = {n}\n")
    f.write(f"e = {e}\n")
    f.write(f"ct = {ct}\n")
    f.write(f"mods = {mods}\n")