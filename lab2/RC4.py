import numpy as np

import utils


class RC4:
    class __RC4Tools:
        def __init__(self, key):
            key_length = len(key)

            self._s = np.arange(256, dtype=np.uint8)
            j = 0
            for i in range(256):
                j = (j + self._s[i] + key[i % key_length]) % 256
                self._s[i], self._s[j] = self._s[j], self._s[i]

        def apply_key(self, data):
            res = []
            i = 0
            j = 0
            for item in data:
                i = (i + 1) % 256
                j = (j + self._s[i]) % 256
                self._s[i], self._s[j] = self._s[i], self._s[j]
                res.append(item ^ self._s[(int(self._s[i]) + int(self._s[j])) % 256])

            return np.array(res, dtype=np.uint8)

    def __init__(self, key):

        self._encoder = self.__RC4Tools(key)
        self._decoder = self.__RC4Tools(key)

    def encrypt(self, plaintext):
        return self._encoder.apply_key(plaintext)

    def decrypt(self, ciphertext):
        return self._decoder.apply_key(ciphertext)


if __name__ == '__main__':
    new_key = bytearray.fromhex("000102030405060708090a0b0c0d0e0f")
    KEY = [w_i for w_i in new_key]
    rc4 = RC4(KEY)
    PLAINTEXT = utils.encode("My name is UNDEF")

    ciphertext = rc4.encrypt(PLAINTEXT)
    res = rc4.decrypt(ciphertext)
    print(utils.decode(res))
