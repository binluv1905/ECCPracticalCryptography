import hashlib
import secrets

from tinyec import ec, registry

import numbertheory

curve = registry.get_curve('secp256r1')


def sha256(msg: str):
    hash_bytes = hashlib.sha256(msg.encode('utf8')).digest()
    return int.from_bytes(hash_bytes, 'big')


def sign(msg, privKey):
    h = sha256(msg)
    k = secrets.randbelow(curve.field.n)
    R = k * curve.g
    r = R.x
    s = pow(k, -1, curve.field.n) * (h + r * privKey) % curve.field.n
    v = R.y % 2
    return (r, s, v)


def verify(msg, pubKey, sig: tuple):
    r, s, v = sig
    h = sha256(msg)
    s1 = pow(s, -1, curve.field.n)
    R1 = (h * s1) % curve.field.n * curve.g + (r * s1) % curve.field.n * pubKey
    r1 = R1.x % curve.field.n
    return r == r1


def recover_public_keys(msg, sig: tuple):
    r, s, v = sig
    h = sha256(msg)
    alpha = (pow(r, 3, curve.field.p) + curve.a * r + curve.b) % curve.field.p
    y = numbertheory.square_root_mod_prime(alpha, curve.field.p)

    R1 = ec.Point(curve, r, y)
    Q1 = pow(r, -1, curve.field.n) * (s * R1 - (h % curve.field.n) * curve.g)

    R2 = ec.Point(curve, r, curve.field.p - y)
    Q2 = pow(r, -1, curve.field.n) * (s * R2 - (h % curve.field.n) * curve.g)

    if bool(v) == bool(y & 1):
        print('Recovered public key: ({}, {})'.format(hex(Q1.x), hex(Q1.y)))
    else:
        print('Recovered public key: ({}, {})'.format(hex(Q2.x), hex(Q2.y)))

    return [Q1, Q2]


#signer_privKey = secrets.randbelow(curve.field.n)
signer_privKey = 83511515771946965281308662496798134449505148460513849820608294042110109431481
signer_pubKey = signer_privKey * curve.g
print('Private key:', signer_privKey)
print('Public key: ({}, {})'.format(hex(signer_pubKey.x), hex(signer_pubKey.y)))

msg = "Test message!"

sig = sign(msg, signer_privKey)
print('Signature:', sig)

sig_verify = verify(msg, signer_pubKey, sig)
print('Signature valid? :', sig_verify)

recoveredPubKeys = recover_public_keys(msg, sig)
for pk in recoveredPubKeys:
    print('Recovered possible public keys: ({}, {})'.format(hex(pk.x), hex(pk.y)))
