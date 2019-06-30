import base64
import hashlib
import random
import string
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, padding

import configuration as config
from configuration import MESSAGE_SEPARATOR as SEP
from utils import logger

hash_algorithm = hashlib.sha1


def cryptographic_checksum(message_bytes):
    """
    :return checksum: bytes array
    """
    return hash_(message_bytes)


def get_timestamp():
    return bytes(str(int(datetime.now().timestamp() * 1e6)), encoding='utf-8')


def get_ticket_life_span():
    return get_timestamp(), bytes(str(int((datetime.now().timestamp() + config.TICKET_LIFE_TIME_MINUTES * 60) * 1e6)),
                                  encoding='utf-8')


def clear_sign(message_bytes, private_key_bytes):
    nonce = generate_nonce()
    timestamp = get_timestamp()
    final_message_bytes = SEP.join([message_bytes, nonce, timestamp])
    signature = sign_message(final_message_bytes, private_key_bytes)

    return SEP.join([final_message_bytes, signature])


def strip_clear_signed_message(clear_signed_message_bytes):
    parts = clear_signed_message_bytes.split(SEP)
    return SEP.join(parts[:-3])


def open_ticket(ticket_bytes, merchant_private_key):
    ticket = decrypt_asym(ticket_bytes, merchant_private_key)
    """
    client_access_symmetric_key,
    client_identity,
    client_address,
    ticket_start_timestamp,
    ticket_end_timestamp
    """
    return ticket.split(SEP)


def verify_clear_signature(clear_signed_message_bytes, public_key_bytes):
    parts = clear_signed_message_bytes.split(SEP)
    message_bytes = SEP.join(parts[:-3])
    nonce = parts[-3]
    timestamp = parts[-2]
    signature = parts[-1]
    verified = verify_signature(public_key_bytes, signature, SEP.join([message_bytes, nonce, timestamp]))
    if not verified:
        logger.log_warn('clear signature verification failed.')

        # TODO timestamp checking!

    return message_bytes, verified


def generate_random_identity():
    return generate_random_bytes(config.IDENTIFIER_LENGTH)


def generate_random_transaction_id():
    return generate_random_bytes(config.TRANSACTION_ID_LENGTH)


def generate_random_bytes(length):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length)).encode('utf-8')


def generate_random_number_bytes(length):
    return ''.join(random.choices(string.digits, k=length)).encode('utf-8')


def generate_epoid_serial_number():
    return generate_random_number_bytes(length=config.EPOID_SERIAL_NUMBER_LENGTH)


def generate_random_account_number():
    return generate_random_number_bytes(config.ACCOUNT_NUMBER_LENGTH)


def generate_nonce():
    return generate_random_bytes(length=config.NONCE_LENGTH)


def two_layer_sym_asym_encode(message_bytes, public_key_bytes):
    nonce = generate_nonce()
    symmetric_key = generate_symmetric_key()
    encrypted_message = encrypt_sym(message_bytes=SEP.join([message_bytes, nonce]), key_bytes=symmetric_key)
    encrypted_key = encrypt_asym(message_bytes=symmetric_key, puk_bytes=public_key_bytes)

    return SEP.join([encrypted_message, encrypted_key])


def two_layer_sym_asym_decode(message_bytes, private_key_bytes):
    enc_message_bytes, enc_key_bytes = message_bytes.split(SEP)
    symmetric_key = decrypt_asym(enc_key_bytes, private_key_bytes)
    plain_bytes = decrypt_sym(enc_message_bytes, symmetric_key)
    plain_message = SEP.join(plain_bytes.split(SEP)[:-1])
    return plain_message


def hash_(byte_message):
    """
    :return hash_value: bytes array
    """
    return hash_algorithm(byte_message).hexdigest().encode('utf-8')


def generate_symmetric_key():
    """
    :return: symmetric_key
    """
    return Fernet.generate_key()


def generate_rsa_private_public_key_pair():
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
    public_key_bytes = __dumps_rsa_puk(public_key)

    return private_key_bytes, public_key_bytes


def get_price_number(price):
    return float(price[:-len(config.CURRENCY)].strip())


def get_price_bytes(price):
    if int(price) == price:
        return bytes(str(int(price)), encoding='utf-8') + config.CURRENCY
    else:
        return bytes(str(price), encoding='utf-8') + config.CURRENCY

def generate_dsa_private_public_key_pair():
    private_key = dsa.generate_private_key(
        key_size=1024,
        backend=default_backend()
    )

    public_key = private_key.public_key()
    private_key_bytes = __dumps_prk(private_key)
    public_key_bytes = __dumps_dsa_puk(public_key)

    return private_key_bytes, public_key_bytes


def dsa_sign(message_bytes, private_key_bytes):
    private_key = __loads_prk(private_key_bytes)
    signature = private_key.sign(
        message_bytes,
        hashes.SHA256()
    ).hex().encode('utf-8')

    return SEP.join([message_bytes, signature])


def dsa_verify(signed_message_bytes, public_key_bytes):
    public_key = __loads_puk(public_key_bytes)
    parts = signed_message_bytes.split(SEP)
    signature = bytes.fromhex(parts[-1].decode('utf-8'))
    message = SEP.join(parts[:-1])

    try:
        public_key.verify(
            signature,
            message,
            hashes.SHA256()
        )
        return message, True
    except InvalidSignature:
        return None, False


def encrypt_sym(message_bytes, key_bytes):
    """
    :param message_bytes: bytes array
    :param key_bytes: key_bytes object
    :return enc_message: bytes array
    """
    fernet = Fernet(key_bytes)
    return fernet.encrypt(message_bytes)


def is_number_valued_bytes(input_bytes):
    for b in input_bytes:
        if not (ord(b'0') <= b <= ord(b'9') or b == ord(b'.')):
            return False
    return True


def decrypt_sym(enc_message_bytes, key_bytes):
    """
    :param enc_message_bytes: bytes array
    :param key_bytes: key_bytes object
    :return message: bytes array
    """
    fernet = Fernet(key_bytes)
    return fernet.decrypt(enc_message_bytes)


def encrypt_asym(message_bytes, puk_bytes):
    key = __loads_puk(puk_bytes)

    cipher_text_hex = key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    cipher_text = base64.encodebytes(cipher_text_hex)

    return cipher_text


def decrypt_asym(cypher_text_bytes, prk_bytes):
    key = __loads_prk(prk_bytes)

    cypher_text_hex = base64.decodebytes(cypher_text_bytes)

    message_bytes = key.decrypt(
        cypher_text_hex,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    return message_bytes


def sign_message(message_bytes, private_key_bytes):
    private_key = __loads_prk(private_key_bytes)

    signature_hex = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    signature = base64.encodebytes(signature_hex)

    return signature


def encrypt_asym_with_signature(message_bytes, sender_prk_bytes, receiver_puk_bytes):
    receiver_puk = __loads_puk(receiver_puk_bytes)

    cipher_text_hex = receiver_puk.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    signature = sign_message(message_bytes, sender_prk_bytes)
    cipher_text = base64.encodebytes(cipher_text_hex)

    return cipher_text, signature


def verify_signature(sender_puk_bytes, signature_bytes, message_bytes):
    sender_puk = __loads_puk(sender_puk_bytes)

    signature_hex = base64.decodebytes(signature_bytes)

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


def decrypt_asym_with_signature(cypher_text_bytes, signature_bytes, receiver_prk_bytes, sender_puk_bytes):
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

    verification = verify_signature(sender_puk, signature_bytes, message_bytes)

    return message_bytes, verification


def __dumps_prk(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


def __dumps_rsa_puk(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1
    )


def __dumps_dsa_puk(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
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
