#!/usr/bin/python
__author__ = 'Ron Li'


class Sha256:
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

    h = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

    def __init__(self):
        self.data_len = 0
        self.bit_len = 0
        self.data_b = [0] * 64
        self.buffer_w = [0] * len(self.h)

    def sha_init(self):
        for i in range(len(self.h)):
            self.buffer_w[i] = (self.h[i])

    def rotr(self, x, y):
        return ((x >> y) | (x << (32-y))) & 0xFFFFFFFF

    def sha_transform(self):
        print("\nsha_transform\n\n")
        print([hex(x) for x in self.data_b])

        m = [0] * 64
        j = 0
        for i in range(16):
            m[i] = self.data_b[j]<<24 | self.data_b[j+1]<<16 | self.data_b[j+2]<<8 | self.data_b[j+3]
            j += 4

        for i in range(16, 64):
            sig0 = self.rotr(m[i-15], 7) ^ self.rotr(m[i-15], 18) ^ (m[i-15] >> 3)
            sig1 = self.rotr(m[i-2], 17) ^ self.rotr(m[i-2], 19) ^ (m[i-2] >> 10)
            m[i] = (sig1 + m[i-7] + sig0 + m[i-16]) & 0xFFFFFFFF

        a,b,c,d,e,f,g,h = self.buffer_w

        for i in range(64):
            ep0 = (self.rotr(a, 2) ^ self.rotr(a, 13) ^ self.rotr(a, 22)) & 0xFFFFFFFF
            ep1 = (self.rotr(e, 6) ^ self.rotr(e, 11) ^ self.rotr(e, 25)) & 0xFFFFFFFF
            ch  = ((e&f) ^ ((~e)&g))
            maj = ((a&b) ^ (a&c) ^ (b&c))
            t1  = (h + ep1 + ch + self.k[i] + m[i]) & 0xFFFFFFFF
            t2 = (ep0 + maj) & 0xFFFFFFFF
            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF

        self.buffer_w[0] = (self.buffer_w[0] + a) & 0xFFFFFFFF
        self.buffer_w[1] = (self.buffer_w[1] + b) & 0xFFFFFFFF
        self.buffer_w[2] = (self.buffer_w[2] + c) & 0xFFFFFFFF
        self.buffer_w[3] = (self.buffer_w[3] + d) & 0xFFFFFFFF
        self.buffer_w[4] = (self.buffer_w[4] + e) & 0xFFFFFFFF
        self.buffer_w[5] = (self.buffer_w[5] + f) & 0xFFFFFFFF
        self.buffer_w[6] = (self.buffer_w[6] + g) & 0xFFFFFFFF
        self.buffer_w[7] = (self.buffer_w[7] + h) & 0xFFFFFFFF

    def sha_update(self, input, len):
        """ Update new data block """
        if isinstance(input, str):
            print("Convert str to bytes\n")
            input = bytearray(input.encode('ascii'))

        for i in range(len):
            self.data_b[self.data_len] = input[i]
            self.data_len += 1
            if self.data_len == 64:
                self.sha_transform()
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

            self.sha_transform()
            self.data_b[:56] = [0 for x in self.data_b[:56]]

        # Append to the padding the total message's length in bits and transform
        self.bit_len += self.data_len * 8

        self.data_b[63] = self.bit_len & 0xFF
        self.data_b[62] = (self.bit_len >> 8 )& 0xFF
        self.data_b[61] = (self.bit_len >> 16)& 0xFF
        self.data_b[60] = (self.bit_len >> 24)& 0xFF
        self.data_b[59] = (self.bit_len >> 32)& 0xFF
        self.data_b[58] = (self.bit_len >> 40)& 0xFF
        self.data_b[57] = (self.bit_len >> 48)& 0xFF
        self.data_b[56] = (self.bit_len >> 56)& 0xFF

        self.sha_transform()

        return self.buffer_w


def uint_test(input):
    """ Unit test for any giving inputs """
    s = Sha256()
    s.sha_init()
    s.sha_update(input, len(input))
    return s.sha_digest()

def main():
    """ Run tests on several unit tests """
    test = 'abc'
    digest = uint_test(test)
    print([hex(x) for x in digest])

    test = ''
    digest = uint_test(test)
    print([hex(x) for x in digest])

    test = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
    digest = uint_test(test)
    print([hex(x) for x in digest])

    test = 'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu'
    digest = uint_test(test)
    print([hex(x) for x in digest])


if __name__=="__main__":
    main()




    