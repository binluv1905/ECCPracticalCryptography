import pickle
import secrets

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from tinyec import registry

curve = registry.get_curve('secp256r1')


def compress(p):
    return hex(p.x) + hex(p.y % 2)[2:]


def encrypt_AES_GCM(plain_text, secret_key):
    aes_cipher = AES.new(secret_key, AES.MODE_GCM)
    cipher_text, auth_tag = aes_cipher.encrypt_and_digest(plain_text)
    return (cipher_text, aes_cipher.nonce, auth_tag)


def decrypt_AES_GCM(cipher_text, nonce, auth_tag, secret_key):
    aes_cipher = AES.new(secret_key, AES.MODE_GCM, nonce)
    plaintext = aes_cipher.decrypt_and_verify(cipher_text, auth_tag)
    return plaintext


def derive_encrypt_key(ephemeral_privkey, receiver_pubkey):
    shared_point = ephemeral_privkey * receiver_pubkey
    password = compress(shared_point)[2:]
    salt = secrets.token_hex(8)
    derive_key = scrypt(password, salt, 32, 16384, 8, 1)
    return (derive_key, salt)


def derive_decrypt_key(receiver_privkey, ephemeral_pubkey, salt):
    shared_point = receiver_privkey * ephemeral_pubkey
    password = compress(shared_point)[2:]
    derive_key = scrypt(password, salt, 32, 16384, 8, 1)
    return derive_key


def encrypt_ECC(plain_text, receiver_pubkey):
    ephemeral_privkey = secrets.randbelow(curve.field.n)
    shared_key, salt = derive_encrypt_key(ephemeral_privkey, receiver_pubkey)
    cipher_text, nonce, auth_tag = encrypt_AES_GCM(plain_text, shared_key)
    ephemeral_pubkey = ephemeral_privkey * curve.g
    return (cipher_text, nonce, auth_tag, salt, ephemeral_pubkey)


def decrypt_ECC(encrypted_msg, receiver_privkey):
    cipher_text, nonce, auth_tag, salt, ephemeral_pubkey = encrypted_msg
    secret_key = derive_decrypt_key(receiver_privkey, ephemeral_pubkey, salt)
    plain_text = decrypt_AES_GCM(cipher_text, nonce, auth_tag, secret_key)
    return plain_text


msg = b'Text to be encrypted by ECC public key and ' \
      b'decrypted by its corresponding ECC private key'
print("Original msg:", msg)


receiver_privkey = secrets.randbelow(curve.field.n)
receiver_pubkey = receiver_privkey * curve.g

# Encrypt
encrypted_msg = encrypt_ECC(msg, receiver_pubkey)
print("Encrypted msg:", encrypted_msg)

# Transfer encrypted data
print("Now transfer the encrypted data (e.g. through Internet)")
data_serialized = pickle.dumps(encrypted_msg, pickle.DEFAULT_PROTOCOL)
data_deserialized = pickle.loads(data_serialized)

# Decrypt
decrypted_msg = decrypt_ECC(data_deserialized, receiver_privkey)
print("Decrypted msg:", decrypted_msg)

print("Equal messages:", msg == decrypted_msg)
