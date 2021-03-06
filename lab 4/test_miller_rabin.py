from random import randint
import tqdm


def is_prime(n, k):
    if n % 2 == 0 and n != 2 or n < 2:
        return False
    if n < 4:
        return True
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = randint(2, n - 1)
        x = pow(a, d, n)
        if x == 1:
            continue
        for _ in range(s):
            if x == n - 1:
                break
            x = x ** 2 % n
        else:
            return False
    return True


if __name__ == '__main__':
    prime_numbers = [6000053, 6000061, 6000073, 6000101, 6000103, 6000109, 6000119, 6000121, 6000149, 6000157,
                     6000173, 6000191, 6000199, 6000221, 6000229, 6000233, 6000271, 6000277, 6000283, 6000301,
                     6000307, 6000317, 6000343, 6000373, 6000377, 6000389, 6000403, 6000427, 6000431, 6000457,
                     6000479, 6000481, 6000503, 6000529, 6000551, 6000557, 6000569, 6000571, 6000581, 6000611,
                     6000619, 6000641, 6000653, 6000679, 6000703, 6000733, 6000773, 6000793, 6000803, 6000809,
                     6000821, 6000823, 6000829, 6000853, 6000857, 6000859, 6000889, 6000893, 6000899, 6000937,
                     6000961, 6000977, 6001013, 6001019, 6001033, 6001043, 6001049, 6001063, 6001069, 6001087,
                     6001109, 6001147, 6001157, 6001189, 6001201, 6001217, 6001249, 6001253, 6001271, 6001277,
                     6001291, 6001297, 6001339, 6001343, 6001351, 6001427, 6001433, 6001439, 6001447, 6001453,
                     6001469, 6001483, 6001517, 6001531, 6001547, 6001577, 6001601, 6001609, 6001613, 6001627,
                     6001669, 6001673, 6001679, 6001717, 6001727, 6001741, 6001747, 6001757, 6001763, 6001789,
                     6001819, 6001829, 6001903, 6001907, 6001909, 6001921, 6001937, 6001939, 6001981, 6001991,
                     6001997, 6002033, 6002047, 6002053, 6002063, 6002083, 6002089, 6002093, 6002111, 6002123,
                     6002131, 6002137, 6002153, 6002179]

    for prime in tqdm.tqdm(prime_numbers):
        if not is_prime(prime, 1000):
            print("ERROR")
    print("Finish")

