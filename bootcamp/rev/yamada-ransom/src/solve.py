from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

def encrypt():
    password = b"ThisIsTheEncryptKey"
    key = hashlib.sha256(password).digest()
    
    iv = b"\x00" * 16
    with open("flag.txt", "rb") as f:
        plaintext = f.read()
    
    padded = pad(plaintext, AES.block_size)
    cbc = AES.new(key, AES.MODE_CBC, iv)
    encrypted_flag = cbc.encrypt(padded)
    
    with open("flag.encrypted", "wb") as f:
        f.write(encrypted_flag)

def decrypt():
    password = b"ThisIsTheEncryptKey"
    key = hashlib.sha256(password).digest()
    
    iv = b"\x00" * 16
    
    with open("flag.encrypted", "rb") as f:
        ctxt = f.read()
    
    cbc = AES.new(key, AES.MODE_CBC, iv)
    plain = unpad(cbc.decrypt(ctxt), AES.block_size)
    
    print("Recovered IV:", iv.hex())
    print("Full plaintext:", plain.decode())

if __name__ == "__main__":
    with open("flag.txt", "wb") as f:
        f.write(b"CTFITB2025{omg99_ry0_d0nt_g1v3_th3m_m4lwar3_alr3ady!_:shakemyhead:}")
    
    encrypt()
    decrypt()