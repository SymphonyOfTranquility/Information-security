from aes_modes.aes import S_BOX, R_CON


def rot_word(word):
    word.append(word.pop(0))
    return word


def sub_word(word):
    return [S_BOX[byte] for byte in word]


def key_expansion(key, nb, nk, nr):
    words = []
    for i in range(nk):
        words.append(key[nb * i: nb * (i + 1)])

    for i in range(nk, nb * (nr + 1)):
        temp = words[-1][:]
        if i % nk == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= R_CON[(i // nk)]
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)

        for j in range(len(temp)):
            temp[j] ^= words[-nk][j]

        words.append(temp)

    return words