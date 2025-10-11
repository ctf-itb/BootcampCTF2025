# generate_payload.py  — SHA-256 key, reverse-built MD5_ARRAY (correct)
# pip install pycryptodome
import hashlib, secrets
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

FLAG = b"CTFITB2025{y34_60d07_15_pr377y_345y_70_r3v3r53_tbh_GG}"

def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()

# ---- choose / control the permutation -------------------------------------------------
# Option 1 (random each run):
perm = list(range(100))
secrets.SystemRandom().shuffle(perm)

# # Option 2 (deterministic from a seed):
# import random
# rnd = random.Random(0xD1T0)  # change seed as desired
# perm = list(range(100))
# rnd.shuffle(perm)
# ---------------------------------------------------------------------------------------

# Precompute md5("0")..md5("99")
tile_md5_map = [md5_hex(str(i)) for i in range(100)]

# Compute idx[k] forward from the rule you'd use at runtime:
#   start idx[0] = 0
#   after selecting perm[k] and removing it, next idx is:
#   idx[k+1] = lower4(md5(perm[k])) % (N - k - 1)
N = len(perm)
idx = [0] * N
for k in range(N - 1):
    md5h = tile_md5_map[perm[k]]
    low4 = int.from_bytes(bytes.fromhex(md5h)[24:32], "big")
    idx[k + 1] = low4 % (N - k - 1)

# Build MD5_ARRAY in REVERSE so that removing at idx each step yields perm
md5_array = []
for k in range(N - 1, -1, -1):
    md5h = tile_md5_map[perm[k]]
    md5_array.insert(idx[k], md5h)

# Derive ChaCha20 key from SHA-256(str(perm))  (Godot will do the same)
key_material = hashlib.sha256(str(perm).encode()).digest()  # 32 bytes
nonce = get_random_bytes(12)                                # 12-byte nonce
cipher = ChaCha20.new(key=key_material, nonce=nonce)
ciphertext = cipher.encrypt(FLAG)

# --- helpers to print in GDScript-friendly form ---------------------------------------
def gd_array_of_strings(lst):
    items = ",\n    ".join(f"\"{s}\"" for s in lst)
    return "[\n    " + items + "\n]"

print("# --- COPY THESE INTO Main.gd ---\n")

print("TILE_MD5_MAP =")
print(gd_array_of_strings(tile_md5_map))

print("\nMD5_ARRAY =")
print(gd_array_of_strings(md5_array))

print("\nENCRYPTED_FLAG_HEX = \"%s\"" % ciphertext.hex())
print("NONCE_HEX = \"%s\"" % nonce.hex())

# Debug preview (safe to leave on while testing; remove for release)
print("\n# DEBUG: first 10 expected tiles if you simulate the walk:")
# quick walk to preview the first few expected tiles
L = md5_array[:]
i = 0
for step in range(min(10, len(L))):
    md5h = L[i]
    tile = tile_md5_map.index(md5h)
    print(f"#  step {step}: expect tile {tile}")
    del L[i]
    if L:
        low4 = int.from_bytes(bytes.fromhex(md5h)[12:16], "big")
        i = low4 % len(L)

print("# SECRET_PERM =", perm)
print("# KEY_SHA256_HEX =", hashlib.sha256(str(perm).encode()).hexdigest())
print("# FLAG_LEN =", len(FLAG))
