#!/usr/bin/python2.7
import struct
from Crypto.Cipher import AES

QUAD = struct.Struct('>Q')

def aes_unwrap_key_and_iv(kek, wrapped):
    n = len(wrapped)/8 - 1
    #NOTE: R[0] is never accessed, left in for consistency with RFC indices
    R = [None]+[wrapped[i*8:i*8+8] for i in range(1, n+1)]
    A = QUAD.unpack(wrapped[:8])[0]
    decrypt = AES.new(kek).decrypt
    for j in range(5,-1,-1): #counting down
        for i in range(n, 0, -1): #(n, n-1, ..., 1)
            ciphertext = QUAD.pack(A^(n*j+i)) + R[i]
            B = decrypt(ciphertext)
            A = QUAD.unpack(B[:8])[0]
            R[i] = B[8:]
    return "".join(R[1:]), A

#key wrapping as defined in RFC 3394
#http://www.ietf.org/rfc/rfc3394.txt
#def aes_unwrap_key(kek, wrapped, iv=0xa6a6a6a6a6a6a6a6):
#Changed iv for Watchguard
def aes_unwrap_key(kek, wrapped, iv=100085249058027875):
    key, key_iv = aes_unwrap_key_and_iv(kek, wrapped)
    if key_iv != iv:
        raise ValueError("Integrity Check Failed: "+hex(key_iv)+" (expected "+hex(iv)+")")
    print key
    #print key_iv
    return key

#alternate initial value for aes key wrapping, as defined in RFC 5649 section 3
#http://www.ietf.org/rfc/rfc5649.txt
def aes_unwrap_key_withpad(kek, wrapped):
    if len(wrapped) == 16:
        plaintext = AES.new(kek).decrypt(wrapped)
        key, key_iv = plaintext[:8], plaintext[8:]
    else:
        key, key_iv = aes_unwrap_key_and_iv(kek, wrapped)
    key_iv = "{0:016X}".format(key_iv)
    if key_iv[:8] != "A65959A6":
        raise ValueError("Integrity Check Failed: "+key_iv[:8]+" (expected A65959A6)")
    key_len = int(key_iv[8:], 16)
    #print key[:key_len]
    return key[:key_len]

def aes_wrap_key(kek, plaintext, iv=0xa6a6a6a6a6a6a6a6):
    n = len(plaintext)/8
    R = [None]+[plaintext[i*8:i*8+8] for i in range(0, n)]
    A = iv
    encrypt = AES.new(kek).encrypt
    for j in range(6):
        for i in range(1, n+1):
            B = encrypt(QUAD.pack(A) + R[i])
            A = QUAD.unpack(B[:8])[0] ^ (n*j + i)
            R[i] = B[8:]
    return QUAD.pack(A) + "".join(R[1:])

def aes_wrap_key_withpad(kek, plaintext):
    iv = 0xA65959A600000000 + len(plaintext)
    plaintext = plaintext + "\0" * ((8 - len(plaintext)) % 8)
    if len(plaintext) == 8:
        return AES.new(kek).encrypt(QUAD.pack[iv] + plaintext)
    return aes_wrap_key(kek, plaintext, iv)

def test():
    #test vector from RFC 3394
    import binascii
    import sys
    #KEK = binascii.unhexlify("000102030405060708090A0B0C0D0E0F")
    KEK = binascii.unhexlify("1d03f58287982bc701227394e498de23")
    array_kek = [ 29, 3, 245, 130, 135, 152, 43, 199, 1, 34, 115, 148, 228, 152, 222, 35 ]
    #print ''.join('{:02x}'.format(x) for x in array_kek)
    #print binascii.hexlify(KEK)
    print "Input PSK: "
    user_input = sys.stdin.readline().translate(None, '+')
    CIPHER = binascii.unhexlify(user_input.strip())
    #CIPHER = binascii.unhexlify("9539C9564FB73887D8CCA21F7B29FD3FE60E471D80C9B371")
    #CIPHER = binascii.unhexlify("0E611DC31F2AEBB4A6E69F2641E1E83D762F514F3636E1EFA86B9BDECFEFADFB")
    #CIPHER = binascii.unhexlify("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
    PLAIN = binascii.unhexlify("00112233445566778899AABBCCDDEEFF")
    #assert aes_unwrap_key(KEK, CIPHER) == PLAIN
    binascii.hexlify(aes_unwrap_key(KEK, CIPHER))
    #assert aes_wrap_key(KEK, PLAIN) == CIPHER

test()
