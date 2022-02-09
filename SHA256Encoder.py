import copy
import struct
import binascii

#only for testing
import hashlib

#2^32 value in hex
POW32 = 0xFFFFFFFF

#Values of the first 32 bits of the fractional parts of the square roots of the first 64 prime number
ROUND_VALUES = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

#Values of the first 32 bits of the fractional parts of the square roots of the first 8 prime numbers
INITIAL_HASH_VALUES = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

#Pre-processing (Padding) big-endian:
def pad_message(msglen):
    mdi = msglen & 0x3F
    length = struct.pack('!Q', msglen << 3)

    #padding byte for 55 is 0x80 and 8 bytes of length fit single 64-byte block
    if mdi < 56:
        padlen = 55 - mdi
    else:
        padlen = 119 - mdi

    return b'\x80' + (b'\x00' * padlen) + length


def rotate_right(x, y):
    return ((x >> y) | (x << (32 - y))) & POW32


def majority(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def choose(x, y, z):
    return (x & y) ^ ((~x) & z)


class SHA256:
    output_size = 8

    #initialize the object state
    def __init__(self, m=None):
        self.counter = 0
        self.cache = b''
        self.ROUND_VALUES = copy.deepcopy(ROUND_VALUES)
        self.INITIAL_HASH_VALUES = copy.deepcopy(INITIAL_HASH_VALUES)

        self.update_with_bytes(m)

    #compression of hash values and given message
    def compress(self, c):
        w = [0] * 64
        w[0:16] = struct.unpack('!16L', c)

        #modify the zero-ed indexes at the end of the array
        for i in range(16, 64):
            s0 = rotate_right(w[i-15], 7) ^ rotate_right(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = rotate_right(w[i-2], 17) ^ rotate_right(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & POW32

        #initialize variables with hash values
        a_temp_hash, b_temp_hash, c_temp_hash, d_temp_hash, e_temp_hash, f_temp_hash, g_temp_hash, h_temp_hash = self.INITIAL_HASH_VALUES

        #compression loop - transforms values of a_temp_hash to h_temp_hash
        for i in range(64):
            s0 = rotate_right(a_temp_hash, 2) ^ rotate_right(a_temp_hash, 13) ^ rotate_right(a_temp_hash, 22)
            temp2 = s0 + majority(a_temp_hash, b_temp_hash, c_temp_hash)
            s1 = rotate_right(e_temp_hash, 6) ^ rotate_right(e_temp_hash, 11) ^ rotate_right(e_temp_hash, 25)
            temp1 = h_temp_hash + s1 + choose(e_temp_hash, f_temp_hash, g_temp_hash) + self.ROUND_VALUES[i] + w[i]

            h_temp_hash = g_temp_hash
            g_temp_hash = f_temp_hash
            f_temp_hash = e_temp_hash
            e_temp_hash = (d_temp_hash + temp1) & POW32
            d_temp_hash = c_temp_hash
            c_temp_hash = b_temp_hash
            b_temp_hash = a_temp_hash
            a_temp_hash = (temp1 + temp2) & POW32

        #modify array final values 
        for i, (x, y) in enumerate(zip(self.INITIAL_HASH_VALUES, [a_temp_hash, b_temp_hash, c_temp_hash, d_temp_hash, e_temp_hash, f_temp_hash, g_temp_hash, h_temp_hash])):
            self.INITIAL_HASH_VALUES[i] = (x + y) & POW32

    def update_with_bytes(self, m):
        if not m:
            return

        self.cache += m
        self.counter += len(m)

        while len(self.cache) >= 64:
            self.compress(self.cache[:64])
            self.cache = self.cache[64:]

    #join array values and return binary representaion of SHA-256 hash value
    def digest_transform(self):
        temp_message = copy.deepcopy(self)
        temp_message.update_with_bytes(pad_message(self.counter))
        data = [struct.pack('!L', i) for i in temp_message.INITIAL_HASH_VALUES[:self.output_size]]
        return b''.join(data)

    #converts binary representation to hexadecimal
    def digest_to_SHA256(self):
        return binascii.hexlify(self.digest_transform()).decode('ascii')

#Interaction with user and printing encrypted message on the screen
msg = input('Provide message to encrypt: ')
test_msg = msg
print('The message you want to encrypt using SHA-256: ' + msg)
encrypted_msg = SHA256()
encrypted_msg.update_with_bytes(msg.encode())
encryption_output = encrypted_msg.digest_to_SHA256()
print('The encrypted message using SHA-256 implementation: ' + encryption_output)
print('\n')
print('-------------------------------------------------------')

#Compare with python standard method
hash_object = hashlib.sha256(test_msg.encode())
hex_dig = hash_object.hexdigest()
print('The encrypted message using standard library: ' + hex_dig)
if (hex_dig == encryption_output) :
    print('The results are the same.')
else :
    print('The results are different.')

