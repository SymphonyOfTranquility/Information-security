from itertools import chain


def array2state(byte_array, nb):
    return [byte_array[nb * i: nb * (i + 1)] for i in range(len(byte_array) // nb)]


def state2array(matrix):
    return list(chain.from_iterable(matrix))


xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


to_bytes = lambda word, s: s.join(["{0:0{1}x}".format(c, 2) for c in word])


def print_state(state, s=""):
    for i, w in enumerate(state):
        print("{})".format(i), to_bytes(w, s))