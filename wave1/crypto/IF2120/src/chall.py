from Crypto.Util.number import getPrime, bytes_to_long as b2l
from w1ntr import flag

p = getPrime(256)
q = getPrime(256)
N = p * q

assert b2l(flag) < N

e = 65537
d = pow(e, -1, (p-1)*(q-1))
ciphertext = pow(b2l(flag), e, N)

with open('output.txt', 'w') as f:
    f.write(f"N = {N}\n")
    f.write(f"e = {e}\n")
    f.write(f"c = {ciphertext}\n")