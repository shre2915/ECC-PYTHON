print("\t\t  Encryption deqcryption using Elliptical Curves")

import tinyec.ec as ec
import tinyec.registry as reg
import secrets                                       #generates secure random numbers for managing secrets.

curve = reg.get_curve('secp192r1')

def compress_point(point):
    return (point.x) + (point.y)

def ecc_enc_key(pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)              #generates secure random integers
    ciphertextPubKey = ciphertextPrivKey * curve.g
    sharedECCKey = pubKey * ciphertextPrivKey
    return (sharedECCKey, ciphertextPubKey)

def ecc_dec_key(privKey, ciphertextPubKey):
    sharedECCKey = ciphertextPubKey * privKey
    return sharedECCKey

privKey = secrets.randbelow(curve.field.n)                      #generates secure random integers
pubKey = privKey * curve.g                                      #ECDH algorithm
print("\nprivate key:\n", (privKey))
print("\npublic key:\n", compress_point(pubKey))

(encryptKey, ciphertextPubKey) = ecc_enc_key(pubKey)
print("\nciphertext pubKey:\n", compress_point(ciphertextPubKey))
print("\nencryption key:\n", compress_point(encryptKey))

decryptKey = ecc_dec_key(privKey, ciphertextPubKey)
print("\ndecryption key:\n", compress_point(decryptKey))
