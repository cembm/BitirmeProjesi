import os
#Testin için "" metni kullanılmıştır
try:
    from Crypto.Cipher import AES
    from Crypto.Cipher import DES
    from Crypto.Cipher import ARC2
    from Crypto.Cipher import Blowfish
    from Crypto.Random import get_random_bytes
    from Crypto.PublicKey import ECC
    from secrets import token_bytes
    from pytea import TEA
    import base64
    import hashlib
    import time
except Exception as e:
    os.system("python --version")
    os.system("pip uninstall pycrypto")
    os.system("pip uninstall crypto")
    os.system("pip install pycryptodome")
    os.system("pip install pytea")
    os.system("cls")
    print(e)
    print("Kütüphaneler yenilendi. Lütfen programı kapatıp yeniden başlatın.")

#Testin için "IstanbulKulturUniversitesiMatematikBilgisayarBolumuKadirCemYunus" metni kullanılmıştır

time_Total = time.perf_counter()

turkish_chars = ["ı", "ü", "ğ", "ş", "ç", "ö"]
key_DES = token_bytes(8)
key_AES = hashlib.sha256(b'1234567891234567').digest()
key_RC2 = b'1234567891234567'
key_Blowfish = b'1234567891234567'
key_Tea = os.urandom(16)

message = str(input("Enter a text: "))

for i in message:
    if i in turkish_chars:
        print("Don't enter turkish characters! ")
        quit()


# DES
def encrypt_DES(msg):
    cipher = DES.new(key_DES, DES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, ciphertext, tag


def decrypt_DES(nonce, ciphertext, tag):
    cipher = DES.new(key_DES, DES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)

    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except:
        return False


time_DES = time.perf_counter()
nonce_DES, ciphertext_DES, tag_DES = encrypt_DES(message)
plaintext_DES = decrypt_DES(nonce_DES, ciphertext_DES, tag_DES)
print (time.perf_counter()-time_DES)

# AES
def encrypt(raw):
    BS = AES.block_size
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

    raw = base64.b64encode(pad(raw).encode('utf8'))
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key=key_AES, mode=AES.MODE_CFB, iv=iv)
    return base64.b64encode(iv + cipher.encrypt(raw))


def decrypt(enc):
    unpad = lambda s: s[:-ord(s[-1:])]

    enc = base64.b64decode(enc)
    iv = enc[:AES.block_size]
    cipher = AES.new(key_AES, AES.MODE_CFB, iv)
    return unpad(base64.b64decode(cipher.decrypt(enc[AES.block_size:])).decode('utf8'))


time_AES = time.perf_counter()
ciphertext_AES = encrypt(message)
plaintext_AES = decrypt(ciphertext_AES)
print (time.perf_counter()-time_AES)

# Blowfish


def encrypt(raw):
    BS = Blowfish.block_size
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

    raw = base64.b64encode(pad(raw).encode('utf8'))
    iv = get_random_bytes(Blowfish.block_size)
    cipher = Blowfish.new(key=key_Blowfish, mode=Blowfish.MODE_CFB, iv=iv)
    return base64.b64encode(iv + cipher.encrypt(raw))


def decrypt(enc):
    unpad = lambda s: s[:-ord(s[-1:])]

    enc = base64.b64decode(enc)
    iv = enc[:Blowfish.block_size]
    cipher = Blowfish.new(key_Blowfish, Blowfish.MODE_CFB, iv)
    return unpad(base64.b64decode(cipher.decrypt(enc[Blowfish.block_size:])).decode('utf8'))

time_Blowfish = time.perf_counter()
ciphertext_Blowfish = encrypt(message)
plaintext_Blowfish = decrypt(encrypt(message))
print (time.perf_counter()-time_Blowfish)

# RC2


def encrypt(raw):
    BS = ARC2.block_size
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

    raw = base64.b64encode(pad(raw).encode('utf8'))
    iv = get_random_bytes(ARC2.block_size)
    cipher = ARC2.new(key=key_RC2, mode=ARC2.MODE_CFB, iv=iv)
    return base64.b64encode(iv + cipher.encrypt(raw))


def decrypt(enc):
    unpad = lambda s: s[:-ord(s[-1:])]

    enc = base64.b64decode(enc)
    iv = enc[:ARC2.block_size]
    cipher = ARC2.new(key_RC2, ARC2.MODE_CFB, iv)
    return unpad(base64.b64decode(cipher.decrypt(enc[ARC2.block_size:])).decode('utf8'))

time_RC2 = time.perf_counter()
ciphertext_RC2 = encrypt(message)
plaintext_RC2 = decrypt(encrypt(message))
print (time.perf_counter()-time_RC2)

# TEA
time_Tea = time.perf_counter()
tea = TEA(key_Tea)
cipher_text_Tea = tea.encrypt(message.encode())
plaint_text_Tea = tea.decrypt(cipher_text_Tea)
print (time.perf_counter()-time_Tea)

# HASH (SHA256)
time_HASH = time.perf_counter()
ciphertext_HASH = hashlib.sha256(message.encode()).digest()
ciphertext_HASH_hex = hashlib.sha256(message.encode()).hexdigest()
print (time.perf_counter()-time_HASH)

#ECC
time_ECC = time.perf_counter()
key = ECC.generate(curve='P-256')
f = open('myprivatekey.pem','wt')
f.write(key.export_key(format='PEM'))
f.close()
f = open('myprivatekey.pem','rt')
key = ECC.import_key(f.read())
print (time.perf_counter()-time_ECC)

print(f"Text to be encrypted: {message}\n")
print(f'Encrypted by DES (mode: EAX): {ciphertext_DES}')
print(f'Encrypted by DES (mode: EAX) HEX: {ciphertext_DES.hex()}')
print(f'Decrypted by DES (mode: EAX): {plaintext_DES}')
print(f"Time DES: {time_DES}\n")
print(f'Encrypted by AES (mode: EAX): {ciphertext_AES}')
print(f'Encrypted by AES (mode: EAX) HEX: {ciphertext_AES.hex()}')
print(f'Decrypted by AES (mode: EAX): {plaintext_AES}')
print(f"Time AES: {time_AES}\n")
print(f'Encrypted by Blowfish (mode: CFB): {ciphertext_Blowfish}')
print(f'Encrypted by Blowfish (mode: CFB) HEX: {ciphertext_Blowfish.hex()}')
print(f'Decrypted by Blowfish (mode: CFB): {plaintext_Blowfish}')
print(f"Time Blowfish: {time_Blowfish}\n")
print(f'Encrypted by RC2 (mode: CFB): {ciphertext_RC2}')
print(f'Encrypted by RC2 (mode: CFB) HEX: {ciphertext_RC2.hex()}')
print(f'Decrypted by RC2 (mode: CFB): {plaintext_RC2}')
print(f"Time RC2: {time_RC2}\n")
print(f'Encrypted by Tea: {cipher_text_Tea}')
print(f'Encrypted by Tea HEX: {cipher_text_Tea.hex()}')
print(f'Decrypted by Tea: {plaint_text_Tea}')
print(f"Time Tea: {time_Tea}\n")
print(f'Encrypted by HASH (mode: SHA256): {ciphertext_HASH}')
print(f'Encrypted by HASH (mode: SHA256) HEX: {ciphertext_HASH_hex}')
print(f'Decryption not possible with HASH SHA256')
print(f"Time HASH: {time_HASH}\n")
print(f'Encrypted by HASH (mode: SHA256): {ciphertext_HASH}')
print(f'Encrypted by HASH (mode: SHA256) HEX: {ciphertext_HASH_hex}')
print(f'Decryption not possible with HASH SHA256')
print(f"Time HASH: {time_HASH}\n")

time_Total = time.perf_counter() - time_Total
print(f"Total time: {time_Total}\n")
