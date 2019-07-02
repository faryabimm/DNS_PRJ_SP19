import random
import string
from datetime import datetime

import configuration as config


def get_timestamp():
    return bytes(str(int(datetime.now().timestamp() * 1e6)), encoding='utf-8')


def get_ticket_life_span():
    return get_timestamp(), bytes(str(int((datetime.now().timestamp() + config.TICKET_LIFE_TIME_MINUTES * 60) * 1e6)),
                                  encoding='utf-8')


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


def get_price_number(price):
    return float(price[:-len(config.CURRENCY)].strip())


def get_price_bytes(price):
    if int(price) == price:
        return bytes(str(int(price)), encoding='utf-8') + config.CURRENCY
    else:
        return bytes(str(price), encoding='utf-8') + config.CURRENCY


def is_number_valued_bytes(input_bytes):
    for b in input_bytes:
        if not (ord(b'0') <= b <= ord(b'9') or b == ord(b'.')):
            return False
    return True
