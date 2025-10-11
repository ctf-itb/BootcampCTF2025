from sage.all import *

# scrambled
SCR = r"whenyhwhenyh: CTFITB2025{https://youtu.be/NhevsYwleAEW=T_-ESndZNfIAdIHGvO}"

START_MARK = "CTFITB2025{"
END_MARK   = "}"

vals = {}
with open("kisah.txt", "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line or "=" not in line:
            continue
        k, v = line.split("=", 1)
        vals[k.strip().lower()] = v.strip()

q = Integer(vals["q"])
Z = Integer(vals["z"])

def to_bits(bb: bytes):
    out = []
    for b in bb:
        for n in range(7):
            out.append(1 if (b & (1 << n)) else 0)
    return out

def from_bits(bits):
    res = bytearray()
    for i in range(0, len(bits), 7):
        chunk = bits[i:i+7]
        val = 0
        for j, bit in enumerate(chunk):
            val |= (int(bit) & 1) << j
        res.append(val)
    return bytes(res)

def bitxor(a, b):
    return [(int(a[i]) ^ int(b[i])) for i in range(len(a))]

def prod_exp(p_list, mod_q, bits, lo=0, hi=None):
    if hi is None: hi = min(len(p_list), len(bits))
    acc = Integer(1); mod_q = Integer(mod_q)
    for i in range(lo, hi):
        if bits[i] == 1:
            acc = (acc * (Integer(p_list[i]) % mod_q)) % mod_q
    return acc

def cfactor_window(primes, x, index_set):
    if x == 1:
        return []
    res = []
    X = Integer(x)
    for i in sorted(index_set):
        p = primes[i]
        while X % p == 0:
            res.append(p)
            X //= p
    return res if X == 1 else None

scr_bytes = SCR.encode("utf-8")
bits_scr = to_bits(scr_bytes)
n = 7 * len(scr_bytes)
p_list = Primes()[:n]

start_b = SCR.find(START_MARK)
if start_b < 0:
    raise RuntimeError(f"Marker '{START_MARK}' not found in SCR.")
start_b += len(START_MARK)
end_b = SCR.find(END_MARK, start_b)
if end_b < 0:
    raise RuntimeError(f"Closing '{END_MARK}' not found in SCR after start marker.")

win_lo = 7 * start_b
win_hi = 7 * end_b
win_indices = set(range(win_lo, win_hi))

Y = prod_exp(p_list, q, bits_scr) % q
invY = pow(Integer(Y), Integer(q - 2), Integer(q))
E = (Z * invY) % q

C = continued_fraction(Integer(E) / Integer(q))
recovered = None
for c in C.convergents():
    k = c.denominator()
    l = (k * E) % q
    if k == 0 or l == 0:
        continue
    Fk  = cfactor_window(p_list, k, win_indices)
    Fl  = cfactor_window(p_list, l, win_indices)
    if Fk is not None and Fl is not None:
        mask = [0] * n
        FF = set((Fk + Fl))
        for i in win_indices:
            if p_list[i] in FF:
                mask[i] = 1
        fixed_bits = bitxor(bits_scr, mask)
        candidate = from_bits(fixed_bits).decode("utf-8", errors="ignore")

        if START_MARK[:-1] in candidate and "}" in candidate[candidate.find(START_MARK[:-1]) + len(START_MARK) - 1:]:
            recovered = candidate
            break

print(recovered)
