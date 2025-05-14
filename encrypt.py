import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes

# Constants
CHUNK_SIZE = 1024
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
ITERATIONS = 100000


def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS
    )
    return kdf.derive(password)


def encrypt_file(filename, password):
    password = password.encode()
    with open(filename, 'rb') as f:
        plaintext = f.read()

    encrypted_data = bytearray()

    for i in range(0, len(plaintext), CHUNK_SIZE):
        chunk = plaintext[i:i+CHUNK_SIZE]
        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
        encrypted_data += salt + nonce + encrypted_chunk

    with open(filename + '.enc', 'wb') as f:
        f.write(encrypted_data)

    print(f"[+] Encrypted '{filename}' → '{filename}.enc'")


def decrypt_file(enc_filename, password):
    password = password.encode()
    with open(enc_filename, 'rb') as f:
        data = f.read()

    output = bytearray()
    i = 0

    while i < len(data):
        salt = data[i:i+SALT_SIZE]
        i += SALT_SIZE
        nonce = data[i:i+NONCE_SIZE]
        i += NONCE_SIZE
        chunk_end = i + CHUNK_SIZE + TAG_SIZE
        encrypted_chunk = data[i:chunk_end]
        i = chunk_end

        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, None)
        output += decrypted_chunk

    out_file = enc_filename.replace(".enc", ".dec")
    with open(out_file, 'wb') as f:
        f.write(output)

    print(f"[+] Decrypted '{enc_filename}' → '{out_file}'")




file_to_encrypt = "example.pdf"  
passkey = "$$$JE"
encrypt_file(file_to_encrypt, passkey)
decrypt_file(file_to_encrypt + ".enc", passkey)