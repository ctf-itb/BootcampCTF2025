import random, string

M_TRUE = b"whenyhwhenyh: CTFITB2025{https://youtu.be/NLphEFOyoqM?si=ST3WMAnGfuKXpzU3}"

START = "CTFITB2025{"
END   = "}"

MODE = "truncate-look"
INNER_PREFIX_KEEP = "https://youtu.be/"
K_BITFLIPS = 48

def safe_alphabet():
    return string.ascii_letters + string.digits + "_-:/?=.&"

def to_bits(bb: bytes):
    out=[]
    for b in bb:
        for k in range(7):
            out.append(1 if (b & (1<<k)) else 0)
    return out

def from_bits(bits):
    res = bytearray()
    for i in range(0, len(bits), 7):
        chunk = bits[i:i+7]
        val = 0
        for j, bit in enumerate(chunk):
            val |= (int(bit)&1) << j
        res.append(val)
    return bytes(res)

def flip_bit_inplace(buf: bytearray, bit_index: int):
    byte_index = bit_index // 7
    bit_in_byte = bit_index % 7
    buf[byte_index] ^= (1 << bit_in_byte)

s = M_TRUE.decode("utf-8")
a = s.find(START)
if a < 0:
    raise ValueError("Marker CTFITB2025{ tidak ditemukan.")
b = s.find(END, a + len(START))
if b < 0:
    raise ValueError("Penutup '}' tidak ditemukan setelah CTFITB2025{.")

inner = s[a + len(START): b]
L = len(inner)

if MODE == "truncate-look":
    keep = INNER_PREFIX_KEEP[:L]
    rest_len = L - len(keep)
    if rest_len < 0:
        keep = keep[:L]
        rest_len = 0
    alph = safe_alphabet().replace("{","").replace("}","")
    rand_tail = "".join(random.choice(alph) for _ in range(rest_len))
    new_inner = keep + rand_tail

    assert len(new_inner) == L

    scrambled = s[:a+len(START)] + new_inner + s[b:]

elif MODE == "bitflip":
    bb = bytearray(M_TRUE)
    bit_lo = 7 * (a + len(START))
    bit_hi = 7 * b
    total_bits = bit_hi - bit_lo
    k = min(K_BITFLIPS, total_bits)
    pos = random.sample(range(bit_lo, bit_hi), k)
    for t in pos:
        flip_bit_inplace(bb, t)
    scrambled = bb.decode("utf-8", errors="ignore")
else:
    raise ValueError("MODE harus 'truncate-look' atau 'bitflip'")

assert len(scrambled) == len(s), "Panjang berubah—CF akan gagal."

ia = scrambled.find(START)
ib = scrambled.find(END, ia + len(START))
new_inner_check = scrambled[ia + len(START): ib]
if ("{" in new_inner_check) or ("}" in new_inner_check):
    raise ValueError("Scrambled inner berisi brace—bisa mengacaukan detector window.")

with open("scrambled.txt","w",encoding="utf-8") as f:
    f.write(scrambled)

print("[ok] scrambled.txt ditulis; panjang tidak berubah.")
