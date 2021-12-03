import os
import hashlib
import random
import math
from datetime import datetime

import utils


def generate_key(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(1, phi)

    g = math.gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = math.gcd(e, phi)

    d = utils.multiplicative_inverse(e, phi)

    return (n, e), (n, d)


def sha256(message: bytes) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(message)
    return hasher.digest()


def mask_generation(seed: bytes, mask_len: int):
    c = 0
    t = b''
    while len(t) < mask_len:
        input_bytes = seed + utils.int2bytes(c, 4)
        t += sha256(input_bytes)
        c += 1
    return t[:mask_len]


def xor(a_bytes: bytes, b_bytes: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(a_bytes, b_bytes))


def encrypt(public_key, plaintext, label=b''):
    N, e = public_key
    k = utils.byte_length(N)
    plaintext_len = len(plaintext)
    s = os.urandom(32)

    db = sha256(label) + b'\x00' * (k - plaintext_len - 2 * 32 - 2) + b'\x01' + plaintext

    masked_db = xor(db, mask_generation(s, k - 32 - 1))
    masked_seed = xor(s, mask_generation(masked_db, 32))

    m = utils.bytes2int(b'\x00' + masked_seed + masked_db)
    c = pow(m, e, N)
    return utils.int2bytes(c)


def decrypt(private_key, cipher_text, label=b''):
    n, key = private_key
    plain_text = pow(utils.bytes2int(cipher_text), key, n)
    plain_text = utils.int2bytes(plain_text)

    k = utils.byte_length(n)

    masked_seed, masked_db = plain_text[-(k - 1): -(k - 32 - 1)], plain_text[-(k - 32 - 1):]

    seed = xor(masked_seed, mask_generation(masked_db, 32))
    db = xor(masked_db, mask_generation(seed, k - 32 - 1))

    assert sha256(label) == db[:32]

    i = 32
    while db[i] == 0:
        i += 1
    return db[i + 1:]


if __name__ == '__main__':
    # p = get_prime(1024)
    # q = get_prime(1024)
    p = 171102589826325167845834851435782377928810418781853674502623377798415534179386206818864267332287995492357046967765102970045387042367415959126529053154408517894267729218828616958599497874843594694184166482973293261111729452406882833630832066003011453769641537397796844525392592577452465024760464513790727112303
    q = 110403986910429243551279423028302488454300327680587995908402565289043627383018485838260677058093200752219723152505256103884100584594761040670884639099721908631410706700163423426322972067759687739826798462657424972911881214659300398212639634520933179113415190379833316981393098088311093675394355167621373804269
    print("Prime p:", p)
    print("Prime q:", q)

    public_key, private_key = generate_key(p, q)

    plaintext = os.urandom(64)

    print("RSA-OAEP")

    for i in [8, 16, 32, 64, 128, 256, 512]:
        plaintext = os.urandom(i)
        print("Plain text:", int.from_bytes(plaintext, 'big'))
        t1 = datetime.now()
        ciphertext = encrypt(public_key, plaintext)
        t2 = datetime.now()
        print("Ciphered text:", utils.bytes2int(ciphertext))
        t3 = datetime.now()
        decrypt_plaintext = decrypt(private_key, ciphertext)
        t4 = datetime.now()
        print("Deciphered text:", utils.bytes2int(decrypt_plaintext))
        print("Encryption time", t2 - t1)
        print("Decryption time:", t4 - t3)
        print("Equal:", plaintext == decrypt_plaintext, end="\n\n")
