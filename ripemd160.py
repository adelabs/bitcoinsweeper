#!/usr/bin/env python
''' RIPEMD-160 implementation
'''
from struct import pack, unpack

######################################################################
# Constants
FFFFFFFF = 0xFFFFFFFF
INIT_STATE = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0) 
CONSTS_L = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
CONSTS_R = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)
KL = sum(((k,) * 16 for k in CONSTS_L), ())
KR = sum(((k,) * 16 for k in CONSTS_R), ())

# Bitwise functions
FUNCTIONS = (lambda x, y, z: x ^ y ^ z                 ,
             lambda x, y, z: (FFFFFFFF-x & z) | (x & y),
             lambda x, y, z: (FFFFFFFF-y | x) ^ z      ,
             lambda x, y, z: (FFFFFFFF-z & y) | (x & z),
             lambda x, y, z: (FFFFFFFF-z | y) ^ x      )
FL = sum(((f,) * 16 for f in FUNCTIONS), ())
FR = tuple(reversed(FL))

# Permutations of `range(16)`, indices of the integer array being compressed
RL = ( 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
       7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
       3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
       1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
       4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13)
RR = ( 5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
       6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
      15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
       8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
      12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11)

# Amounts of left rotations
Rol = lambda s, x: (x << s) | (x >> (32-s))
SL = (11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
       7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
      11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
      11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
       9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6)
SR = ( 8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
       9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
       9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
      15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
       8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11)

######################################################################
def Step(x, f, k, s, a, b, c, d, e):
    ''' Each step processes the tuple(a,b,c,d,e) '''
    return (e,
            (Rol(s, (a+f(b,c,d)+x+k)&FFFFFFFF) + e) & FFFFFFFF,
            b,
            ((c << 10) & FFFFFFFF) | (c >> 22),
            d)

def Compression(state, x):
    ''' Compress 16 64-bit integers '''
    left = right = state
    for r, f, k, s in zip(RL, FL, KL, SL):
        left = Step(x[r], f, k, s, *left)
    for r, f, k, s in zip(RR, FR, KR, SR):
        right = Step(x[r], f, k, s, *right)
    return ((state[1] + left[2] + right[3]) & FFFFFFFF,
            (state[2] + left[3] + right[4]) & FFFFFFFF,
            (state[3] + left[4] + right[0]) & FFFFFFFF,
            (state[4] + left[0] + right[1]) & FFFFFFFF,
            (state[0] + left[1] + right[2]) & FFFFFFFF)

def Ripemd160(data):
    ''' Equivalent to hashlib.new('ripemd160', data).digest() '''
    data += '\x80' + '\0'*(64-(len(data)+1+8)%64) + pack('<Q', len(data)*8)
    state = INIT_STATE
    for i in xrange(0, len(data), 64):
        state = Compression(state, unpack('<16L', data[i:i+64]))
    return pack('<5L', *state)

######################################################################
if __name__ == '__main__':
    ''' Unit test '''
    import hashlib
    from util import IntToStr
    for i in xrange(1000):
        data = hashlib.sha256(IntToStr(i)).digest()
        assert Ripemd160(data) == hashlib.new('ripemd160', data).digest()

######################################################################
