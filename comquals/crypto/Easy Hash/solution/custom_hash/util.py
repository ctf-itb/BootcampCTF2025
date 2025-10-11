
# Useful constant (bytes)

SHA1_DIGEST_SIZE = 20
SHA256_DIGEST_SIZE = 32
SHA512_DIGEST_SIZE = 64
MD4_DIGEST_SIZE = 16 
MD5_DIGEST_SIZE = 16

SHA1_STATE_BLOCKS_NUM = 5
SHA256_STATE_BLOCKS_NUM = 8
SHA512_STATE_BLOCKS_NUM = 8
MD4_STATE_BLOCKS_NUM = 4
MD5_STATE_BLOCKS_NUM = 4

# Split the hash from Big-endian hash functions [Sha1, Sha256, Sha512]
def recover_big_endian_state(hexdigest : str, hexdigest_size : int, state_blocks : int):
    state = []
    if len(hexdigest) != hexdigest_size:
        raise ValueError(f"The input hash must be {hexdigest_size} bytes long.")
    for i in range(0,len(hexdigest),hexdigest_size//state_blocks):
        temp = hexdigest[i:i+hexdigest_size//state_blocks]
        state.append(int(temp,16))
    return state

# Split the hash from Little-endian hash functions [MD4, MD5]
def recover_little_endian_state(hexdigest : str):
    if len(hexdigest) != 32:
        raise ValueError("The input hash must be 32 bytes long.")
    # Split the hash into 4 equal parts
    parts = [hexdigest[i:i + 8] for i in range(0, 32, 8)]
    # Convert each part to little-endian format
    little_endian_parts = []
    for part in parts:
        temp = ""
        little_endian = part[::-1] # Revert It
        for j in range(0,len(little_endian),2): # For every hex digit
            temp += little_endian[j+1] + little_endian[j] # Make it little endian
        little_endian_parts.append(temp) 
    A = int(little_endian_parts[0],16)
    B = int(little_endian_parts[1],16)
    C = int(little_endian_parts[2],16)
    D = int(little_endian_parts[3],16)
    return A,B,C,D

def sha1state(hexdigest : str):
    return recover_big_endian_state(hexdigest, SHA1_DIGEST_SIZE * 2, SHA1_STATE_BLOCKS_NUM)

def sha256state(hexdigest : str):
    return recover_big_endian_state(hexdigest, SHA256_DIGEST_SIZE * 2, SHA256_STATE_BLOCKS_NUM)

def sha512state(hexdigest : str):
    return recover_big_endian_state(hexdigest, SHA512_DIGEST_SIZE * 2, SHA512_STATE_BLOCKS_NUM)

def md4state(hexdigest : str):
    return recover_little_endian_state(hexdigest)

def md5state(hexdigest : str):
    return recover_little_endian_state(hexdigest)



def pad(plain : bytes, func : str, block_idx : int = 0, secret_prefix : int = 0):
    plain = b"\x00" * secret_prefix + plain
    if func == "MD4" or func == "MD5":  
        block_size, message_size_bytes, endian = 64, 8, "little"
    elif func == "SHA1" or func == "SHA256":  
        block_size, message_size_bytes, endian = 64, 8, "big"
    elif func == "SHA512":
        block_size, message_size_bytes, endian = 128, 16, "big"
    else:
        raise ValueError("Hash function not supported")

    return plain[secret_prefix::] + b"\x80" + b"\x00" * ((block_size - len(plain) - 1 - message_size_bytes) % block_size) + ((len(plain) + block_idx * block_size) * 8).to_bytes(message_size_bytes, byteorder=endian)

def pad_sha512(plain : bytes, block_idx : int = 0, secret_prefix : int = 0):
    return pad(plain, "SHA512", block_idx, secret_prefix)

def pad_sha256(plain : bytes, block_idx : int = 0, secret_prefix : int = 0):
    return pad(plain, "SHA256", block_idx, secret_prefix)

def pad_sha1(plain : bytes, block_idx : int = 0, secret_prefix : int = 0):
    return pad(plain, "SHA1", block_idx, secret_prefix)

def pad_md4(plain: bytes, block_idx : int = 0, secret_prefix : int = 0):
    return pad(plain, "MD4", block_idx, secret_prefix)

def pad_md5(plain: bytes, block_idx : int = 0, secret_prefix : int = 0):
    return pad(plain, "MD5", block_idx, secret_prefix)