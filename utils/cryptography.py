import hashlib

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
    pass


def generate_private_public_key_pair():
    """
    :return: private_key, public_key
    """
    pass


def encrypt(message, key):
    """
    :param message: bytes array
    :param key: key object
    :return enc_message: bytes array
    """
    pass


def decrypt(enc_message, key):
    """
    :param enc_message: bytes array
    :param key: key object
    :return message: bytes array
    """
    pass
