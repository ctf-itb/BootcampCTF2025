
from custom_hash.util import pad_sha256, sha256state
from custom_hash import SHA256
from pwn import remote
from hashlib import sha256
from libnum import s2n, n2s
import base64

conn = remote("localhost", 8570)
conn.sendlineafter(b": ", b"1")

conn.sendlineafter(b">>> ", b"banana")
conn.recvuntil(b": ")
token, mac = base64.b64decode(conn.recvline().decode().strip()).split(b":::hmac=")

enc = []
for i in range(0, 70, 3):
    forged_mac = SHA256.sha256(message=pad_sha256(f":::authorized=true:::user_id={bin(i)[2::]}".encode(), block_idx=2), state=sha256state(mac)).hex()
    new_token = base64.b64encode(pad_sha256(token, secret_prefix=32) + f":::authorized=true:::user_id={bin(i)[2::]}".encode() + b":::hmac=" + forged_mac.encode())

    conn.sendlineafter(b": ", b"3")
    conn.sendlineafter(b": ", new_token)
    conn.recvuntil(b"...\n")
    conn.recvuntil(b"...\n")
    enc.append(int(conn.recvline().strip().decode()))


flag = b"CTFITB202"
prev1 = s2n(sha256(b"202").digest())
prev2 = s2n(sha256(b"ITB").digest())
for i in range(1, len(enc)):
    assert enc[i] % (prev1 * prev2) == 0
    hashed = enc[i] // (prev1 * prev2)
    found = False
    for b1 in range(256):
        for b2 in range(256):
            for b3 in range(256):
                plain = bytes([b1, b2, b3])
                if s2n(sha256(plain).digest()) == hashed:
                    flag += plain
                    print(plain)
                    found = True
                    break
            if found:
                break
        if found:
            break
    prev2 = prev1
    prev1 = hashed

print(flag)

