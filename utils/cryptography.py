import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

hash_algorithm = hashlib.sha1


def cryptographic_checksum(byte_message):
    """
    :return checksum: bytes array
    """
    return hash_(byte_message)


def hash_(byte_message):
    """
    :return hash_value: bytes array
    """
    return hash_algorithm(byte_message).digest


def generate_symmetric_key():
    """
    :return: symmetric_key
    """
    return Fernet.generate_key()


def generate_private_public_key_pair():
    """
    :return: private_key, public_key
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    private_key_bytes = __dumps_prk(private_key)
    public_key_bytes = __dumps_puk(public_key)

    return private_key_bytes, public_key_bytes


def encrypt_sym(message, key):
    """
    :param message: bytes array
    :param key: key object
    :return enc_message: bytes array
    """
    fernet = Fernet(key)
    return fernet.encrypt(message)


def decrypt_sym(enc_message, key):
    """
    :param enc_message: bytes array
    :param key: key object
    :return message: bytes array
    """
    fernet = Fernet(key)
    return fernet.decrypt(enc_message)


def encrypt_asym(message_bytes, sender_prk_bytes, receiver_puk_bytes):
    sender_prk = __loads_prk(sender_prk_bytes)
    receiver_puk = __loads_puk(receiver_puk_bytes)

    cipher_text_hex = receiver_puk.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    cipher_text = base64.encodebytes(cipher_text_hex)

    signature_hex = sender_prk.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    signature = base64.encodebytes(signature_hex)

    return cipher_text, signature


def __verify_signature(sender_puk, signature_hex, message_bytes):
    try:
        sender_puk.verify(
            signature_hex,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def decrypt_asym(cypher_text_bytes, signature_bytes, receiver_prk_bytes, sender_puk_bytes):
    signature_hex = base64.decodebytes(signature_bytes)
    cypher_text_hex = base64.decodebytes(cypher_text_bytes)

    receiver_prk = __loads_prk(receiver_prk_bytes)
    sender_puk = __loads_puk(sender_puk_bytes)

    message_bytes = receiver_prk.decrypt(
        cypher_text_hex,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    verification = __verify_signature(sender_puk, signature_hex, message_bytes)

    return message_bytes, verification


def __dumps_prk(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


def __dumps_puk(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1
    )


def __loads_prk(private_key_bytes):
    return serialization.load_pem_private_key(
        private_key_bytes,
        None,
        default_backend()
    )


def __loads_puk(public_key_bytes):
    return serialization.load_pem_public_key(
        public_key_bytes,
        default_backend()
    )
