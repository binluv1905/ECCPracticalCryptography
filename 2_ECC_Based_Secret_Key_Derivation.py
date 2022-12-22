import secrets

from tinyec import registry

curve = registry.get_curve('secp256r1')


def compress(p):
    return hex(p.x) + hex(p.y % 2)[2:]


def ecc_calc_encrypt_keys(pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    sharedECCKey = pubKey * ciphertextPrivKey
    return (sharedECCKey, ciphertextPubKey)


def ecc_calc_decrypt_key(privKey, ciphertextPubKey):
    sharedECCKey = ciphertextPubKey * privKey
    return sharedECCKey


# Generate receiver's private key, public key
privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g
print("Private key:", hex(privKey))
print("Public key:", compress(pubKey))

# Sender
(encryptKey, ciphertextPubKey) = ecc_calc_encrypt_keys(pubKey)
print("Ciphertext pubKey:", compress(ciphertextPubKey))
print("Encrypt key:", compress(encryptKey))

# Receiver
decryptKey = ecc_calc_decrypt_key(privKey, ciphertextPubKey)
print("Decrypt key:", compress(decryptKey))

print("Equal shared keys:", encryptKey == decryptKey)
