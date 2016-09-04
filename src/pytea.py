# -*- coding: utf-8 -*-
'''
Created on 2014-07-16
@summary: Just a pure python module for encrypt and decrypt with interleaving 
          and random padding random number tea.
@author: fiefdx
'''

import os
import sys
import struct
import logging
import time
import binascii
import array

from random import seed
from random import randint

LOG = logging.getLogger(__name__)

tea_num = 32
delta = 0x9e3779b9
op_32 = 0xffffffff
op_64 = 0xffffffffffffffff

def get_encrype_length(length):
    fill_n = (8 - (length + 2))%8 + 2
    result = 1 + length + fill_n + 7
    return result

def get_tea_sum(tea_num, delta):
    tea_sum = 0
    for i in xrange(tea_num):
        tea_sum += delta
    return tea_sum&op_32

def tea_encrypt(v, k):
    '''
    v is utf-8
    '''
    v0, v1 = struct.unpack(">LL", v)
    k0, k1, k2, k3 = struct.unpack(">LLLL", k)
    # delta = 0x9e3779b9
    # delta = 0x12342341
    tea_sum = 0
    for i in xrange(tea_num):
        tea_sum += delta
        tea_sum &= op_32
        v0 += ((((v1 << 4) & op_32) + k0) ^ (v1 + tea_sum) ^ (((v1 >> 5) & op_32) + k1))
        v0 &= op_32
        v1 += ((((v0 << 4) & op_32) + k2) ^ (v0 + tea_sum) ^ (((v0 >> 5) & op_32) + k3))
        v1 &= op_32
    return struct.pack('>LL', v0, v1)

def tea_decrypt(v, k):
    '''
    v is utf-8
    '''
    v0, v1 = struct.unpack(">LL", v)
    k0, k1, k2, k3 = struct.unpack(">LLLL", k)
    # delta = 0x9e3779b9
    # delta = 0x12342341
    tea_sum = get_tea_sum(tea_num, delta)
    for i in xrange(tea_num):
        v1 -= (((v0 << 4) + k2) ^ (v0 + tea_sum) ^ ((v0 >> 5) + k3))
        v1 &= op_32
        v0 -= (((v1 << 4) + k0) ^ (v1 + tea_sum) ^ ((v1 >> 5) + k1))
        v0 &= op_32
        tea_sum -= delta
        tea_sum &= op_32
    return struct.pack('>LL', v0, v1)

def str_encrypt(v, k):
    '''
    v is unicode or string
    k is md5 unicode
    return string
    '''
    v = v.encode("utf-8") if isinstance(v, unicode) else v
    k = str(k)
    # ascii str to bin str
    k = binascii.unhexlify(k)
    result = ""
    cipertext = op_64
    pre_plaintext = op_64
    end_char = "\0"
    fill_n_or = 0xf8
    v_length = len(v)
    fill_n = (8 - (v_length + 2))%8 + 2
    fill_s = ""
    for i in xrange(fill_n):
        fill_s = fill_s + chr(randint(0, 0xff))
        # fill_s = fill_s + chr(0x02)
    v = (chr((fill_n - 2) | fill_n_or) + fill_s + v + end_char * 7)

    for i in xrange(0, len(v), 8):
        if i == 0:
            encrypt_text = tea_encrypt(v[i:i + 8], k)
            result += encrypt_text
            cipertext = struct.unpack(">Q", encrypt_text)[0]
            pre_plaintext = struct.unpack(">Q", v[i:i + 8])[0]
        else:
            plaintext = struct.unpack(">Q", v[i:i + 8])[0] ^ cipertext
            encrypt_text = tea_encrypt(struct.pack(">Q", plaintext), k)
            encrypt_text = struct.pack(">Q", struct.unpack(">Q", encrypt_text)[0] ^ pre_plaintext)
            result += encrypt_text
            cipertext = struct.unpack(">Q", encrypt_text)[0]
            pre_plaintext = plaintext
    # bin to ascii return is str not unicode
    return binascii.hexlify(result)

def str_decrypt(v, k):
    '''
    v is unicode or string
    k is md5 unicode
    return string
    '''
    v = v.encode("utf-8") if isinstance(v, unicode) else v
    k = str(k)
    # ascii to bin
    v = binascii.unhexlify(v)
    k = binascii.unhexlify(k)
    result = ""
    cipertext = op_64
    pre_plaintext = op_64
    pos = 0
    for i in xrange(0, len(v), 8):
        if i == 0:
            cipertext = struct.unpack(">Q", v[i:i + 8])[0]
            plaintext = tea_decrypt(v[i:i + 8], k)
            pos = (ord(plaintext[0]) & 0x07) + 2
            result += plaintext
            pre_plaintext = struct.unpack(">Q", plaintext)[0]
        else:
            encrypt_text = struct.pack(">Q", struct.unpack(">Q", v[i:i + 8])[0] ^ pre_plaintext)
            plaintext = tea_decrypt(encrypt_text, k)
            plaintext = struct.unpack(">Q", plaintext)[0] ^ cipertext
            result += struct.pack(">Q", plaintext)
            pre_plaintext = plaintext ^ cipertext
            cipertext = struct.unpack(">Q", v[i:i + 8])[0]

    # if result[-7:] != "\0" * 7: return None
    if result[-7:] != "\0" * 7: return ""
    # return str not unicode
    return result[pos + 1: -7]