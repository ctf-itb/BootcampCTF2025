from pwn import *

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def blocks(x, n):
    return [x[i : i + n] for i in range(0, len(x), n)]

prefix = b"Whoooopsssie... "[:16]

# io = process(["python3", "vault.py"])
io = remote("127.0.0.1", 8017)

io.sendlineafter(b"iv: ", (b"\x00" * 16).hex().encode())
ct1 = bytes.fromhex(io.recvlineS().strip())

io.sendlineafter(b"iv: ", xor(prefix, ct1).hex().encode())
ct2 = bytes.fromhex(io.recvlineS().strip())

enc1 = blocks(ct1, 16)
enc2 = blocks(ct2, 16)

pt = prefix

for x, y in zip(enc2, enc1[1:]):
    pt += xor(xor(x, pt[-16:]), y)
print(pt)