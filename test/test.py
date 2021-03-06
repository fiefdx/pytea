# -*- coding: utf-8 -*-
'''
Created on 2014-11-17
@summary: test for pytea
@author: fiefdx
'''
import os
import sys
import time
import random
import hashlib
import chardet

import pytea.pytea as tea
EncryptStr = tea.str_encrypt
DecryptStr = tea.str_decrypt

def md5twice(content):
    '''
    param content must be unicode
    result is unicode
    '''
    m = hashlib.md5(content.encode("utf-8")).hexdigest()
    result = hashlib.md5(m).hexdigest().decode("utf-8")
    return result

if __name__ == "__main__":
    string_unicode_en = u"This is a test for English string!"
    string_unicode_cn = u"这是一个中文测试字符串！"
    string_utf_8_en = string_unicode_en.encode("utf-8")
    string_utf_8_cn = string_unicode_cn.encode("utf-8")
    key_unicode = md5twice(u"testkey")

    print ">>>>>>>>>>>>>>>>>> Test Start <<<<<<<<<<<<<<<<<<"

    print "Original String En: ", string_unicode_en
    encrypted_string_en = EncryptStr(string_unicode_en, key_unicode) # is unicode
    print isinstance(encrypted_string_en, unicode)
    print isinstance(encrypted_string_en, str)
    # print chardet.detect(encrypted_string_en)
    print "Encrypted String En: ", encrypted_string_en
    decrypted_string_en = DecryptStr(encrypted_string_en, key_unicode) # is unicode
    print isinstance(decrypted_string_en, unicode)
    print isinstance(decrypted_string_en, str)
    # print chardet.detect(decrypted_string_en)
    print "Decrypted String En: ", decrypted_string_en
    print isinstance(decrypted_string_en, unicode)
    print isinstance(decrypted_string_en, str)

    print "\n"

    print "Original String Cn: ", string_unicode_cn
    encrypted_string_cn = EncryptStr(string_unicode_cn, key_unicode) # is unicode
    print isinstance(encrypted_string_cn, unicode)
    print isinstance(encrypted_string_cn, str)
    # print chardet.detect(encrypted_string_en)
    print "Encrypted String Cn: ", encrypted_string_cn
    decrypted_string_cn = DecryptStr(encrypted_string_cn, key_unicode) # is unicode
    print isinstance(decrypted_string_cn, unicode)
    print isinstance(decrypted_string_cn, str)
    # print chardet.detect(decrypted_string_cn)
    print "Decrypted String Cn: ", decrypted_string_cn

    print ">>>>>>>>>>>>>>>>>>> Test End <<<<<<<<<<<<<<<<<<<"