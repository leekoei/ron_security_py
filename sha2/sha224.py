#!/usr/bin/env python3
__author__ = 'Ron Li'


class Sha224:
    """ A class to calculate SHA224 """

    """
    Initialize table of round constants:
    first 32 bits of the fractional parts of
    the cube roots of the first 64 primes 2..311
    """
    k = (0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
         0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
         0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
         0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
         0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
         0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
         0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
         0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
         0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
         0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
         0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
         0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
         0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
         0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
         0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
         0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)

    """
    Initialize variables:
    The second 32 bits of the fractional parts of
    the square roots of the 9th through 16th primes 23..53
    """
    h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
         0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]

    def __init__(self):
        self.data_len = 0
        self.bit_len = 0
        self.data_b = [0] * 64

    def sha_init(self):
        """ Nothing to be initialized in algorithm level so far """
        pass

    def rotr(self, x, y):
        """ Rigth rotate operation """
        return ((x >> y) | (x << (32-y))) & 0xFFFFFFFF

    def sha_process(self):
        """ Process the message in successive 512-bit chunks """

        # Break chunk into sixteen 32-bit big-endian words m[0..15]
        m = [0] * 64
        # Extend the sixteen 32-bit words into sixty-four 32-bit words
        j = 0
        for i in range(16):
            m[i] = self.data_b[j] << 24 | self.data_b[j+1] << 16\
                | self.data_b[j+2] << 8 | self.data_b[j+3]
            j += 4

        for i in range(16, 64):
            sig0 = self.rotr(m[i-15], 7) ^ self.rotr(m[i-15], 18)\
                ^ (m[i-15] >> 3)
            sig1 = self.rotr(m[i-2], 17) ^ self.rotr(m[i-2], 19)\
                ^ (m[i-2] >> 10)
            m[i] = (sig1 + m[i-7] + sig0 + m[i-16]) & 0xFFFFFFFF

        # Initialize hash value for this chunk
        a, b, c, d, e, f, g, h = self.h

        for i in range(64):
            ep0 = (self.rotr(a, 2) ^ self.rotr(a, 13) ^ self.rotr(a, 22))\
                & 0xFFFFFFFF
            ep1 = (self.rotr(e, 6) ^ self.rotr(e, 11) ^ self.rotr(e, 25))\
                & 0xFFFFFFFF
            ch = ((e & f) ^ ((~e) & g))
            maj = ((a & b) ^ (a & c) ^ (b & c))
            t1 = (h + ep1 + ch + self.k[i] + m[i]) & 0xFFFFFFFF
            t2 = (ep0 + maj) & 0xFFFFFFFF
            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF

        # Add this chunk's hash to result so far
        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + e) & 0xFFFFFFFF
        self.h[5] = (self.h[5] + f) & 0xFFFFFFFF
        self.h[6] = (self.h[6] + g) & 0xFFFFFFFF
        self.h[7] = (self.h[7] + h) & 0xFFFFFFFF

    def sha_update(self, input, len):
        """ Update new data block """

        # Convert string input to bytearray, if needed
        if isinstance(input, str):
            print("Convert str to bytes\n")
            input = bytearray(input.encode('ascii'))

        # Break message into 512-bit chunks
        for i in range(len):
            self.data_b[self.data_len] = input[i]
            self.data_len += 1
            if self.data_len == 64:
                self.sha_process()
                self.bit_len += 512
                self.data_len = 0

    def sha_digest(self):
        """ Calculate the digest """

        i = self.data_len

        # Pad whatever data is left in the buffer
        if self.data_len < 56:
            self.data_b[i] = 0x80
            i += 1
            while i < 56:
                self.data_b[i] = 0x00
                i += 1
        else:
            self.data_b[i] = 0x80
            i += 1
            while i < 64:
                self.data_b[i] = 0x00
                i += 1

            self.sha_process()
            self.data_b[:56] = [0 for x in self.data_b[:56]]

        # Append length of message in bits, as 64-bit big-endian integer
        self.bit_len += self.data_len * 8

        self.data_b[63] = self.bit_len & 0xFF
        self.data_b[62] = (self.bit_len >> 8) & 0xFF
        self.data_b[61] = (self.bit_len >> 16) & 0xFF
        self.data_b[60] = (self.bit_len >> 24) & 0xFF
        self.data_b[59] = (self.bit_len >> 32) & 0xFF
        self.data_b[58] = (self.bit_len >> 40) & 0xFF
        self.data_b[57] = (self.bit_len >> 48) & 0xFF
        self.data_b[56] = (self.bit_len >> 56) & 0xFF

        # Final transform to get final digest
        self.sha_process()

        return self.h[:7]


def uint_test(input):
    """ Unit test for any giving inputs """

    s = Sha224()
    s.sha_update(input, len(input))
    return s.sha_digest()


def main():
    """
    Run tests on several unit tests
    From https://www.di-mgt.com.au/sha_testvectors.html
    """
    test = 'abc'
    digest = uint_test(test)
    print([hex(x) for x in digest])

    test = ''
    digest = uint_test(test)
    print([hex(x) for x in digest])

    test = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
    digest = uint_test(test)
    print([hex(x) for x in digest])

    test = """abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijkl
        mnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"""
    digest = uint_test(test)
    print([hex(x) for x in digest])


if __name__ == "__main__":
    main()
