import math
import random
import os
from datetime import datetime

from utils import get_prime, multiplicative_inverse


def generate_key(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(1, phi)

    g = math.gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = math.gcd(e, phi)

    d = multiplicative_inverse(e, phi)
    dp = d % (p - 1)
    dq = d % (q - 1)

    q_inv = multiplicative_inverse(q, p)

    return (n, e), (p, q, dp, dq, q_inv)


def encrypt(pk, plaintext):
    n, key = pk
    ciphertext = pow(plaintext, key, n)
    return ciphertext


def decrypt(pk, ciphertext):
    p, q, dp, dq, q_inv = pk

    m1 = pow(ciphertext, dp, p)
    m2 = pow(ciphertext, dq, q)
    h = (q_inv * (m1 - m2)) % p
    m = m2 + h * q
    return m


if __name__ == '__main__':
    # p = get_prime(1024)
    # q = get_prime(1024)
    p = 171102589826325167845834851435782377928810418781853674502623377798415534179386206818864267332287995492357046967765102970045387042367415959126529053154408517894267729218828616958599497874843594694184166482973293261111729452406882833630832066003011453769641537397796844525392592577452465024760464513790727112303
    q = 110403986910429243551279423028302488454300327680587995908402565289043627383018485838260677058093200752219723152505256103884100584594761040670884639099721908631410706700163423426322972067759687739826798462657424972911881214659300398212639634520933179113415190379833316981393098088311093675394355167621373804269
    print("Prime p:", p)
    print("Prime q:", q)

    public_key, private_key = generate_key(p, q)

    plaintext = int.from_bytes(os.urandom(64), 'big')

    print("\nRSA Chinese")

    for i in [8, 16, 32, 64, 128, 256, 512]:
        plaintext = int.from_bytes(os.urandom(i), 'big')
        print("Plain text:", plaintext)
        t1 = datetime.now()
        ciphertext = encrypt(public_key, plaintext)
        t2 = datetime.now()
        print("Ciphered text:", ciphertext)
        t3 = datetime.now()
        decrypt_plaintext = decrypt(private_key, ciphertext)
        t4 = datetime.now()
        print("Deciphered text:", decrypt_plaintext)

        print("Encryption time:", t2 - t1)
        print("Decryption time:", t4 - t3)
        print("Equal:",  plaintext == decrypt_plaintext, end='\n\n')