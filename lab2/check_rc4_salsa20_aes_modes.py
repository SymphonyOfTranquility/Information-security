from RC4 import RC4
from Salsa20 import Salsa
from aes_modes.cbc import CBCMode
from aes_modes.cfb import CFBMode
from aes_modes.ctr import CTRMode
from aes_modes.ecb import ECBMode
from aes_modes.ofb import OFBMode

from aes_modes.aes.aes import AES, AES_TYPE

import utils

import numpy as np

from datetime import datetime


def get_time(cipher, message, name):
    t1 = datetime.now()
    cipher.encrypt(message)
    print("{} :".format(name), datetime.now() - t1)


if __name__ == "__main__":
    data = np.random.randint(256, size=(16 * 4 * 1024 * 10,), dtype=np.uint8)

    key = bytearray.fromhex("000102030405060708090a0b0c0d0e0f")
    KEY = [w_i for w_i in key]

    rc4 = RC4(KEY)
    aes_cbc_128 = CBCMode(AES(key, AES_TYPE.AES_128), 16)
    aes_cfb_128 = CFBMode(AES(key, AES_TYPE.AES_128), 16)
    aes_ecb_128 = ECBMode(AES(key, AES_TYPE.AES_128), 16)
    aes_ctr_128 = CTRMode(AES(key, AES_TYPE.AES_128), 16)
    aes_ofb_128 = OFBMode(AES(key, AES_TYPE.AES_128), 16)
    salsa20 = Salsa(KEY+KEY)

    get_time(rc4, data.tolist(), "RC4")
    get_time(aes_cbc_128, data, "CBC mode")
    get_time(aes_cfb_128, data, "CFB mode")
    get_time(aes_ecb_128, data, "ECB mode")
    get_time(aes_ctr_128, data, "CTR mode")
    get_time(aes_ofb_128, data, "OFB mode")
    get_time(salsa20, data.tolist(), "Salsa20")
