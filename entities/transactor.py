from flask import Flask, request

import configuration as config
import static
from configuration import MESSAGE_SEPARATOR as SEP
from entities.psudonym_types import PsudonymTypes
from static import slash_contain as slash
from utils import cryptography
from utils import logger
from utils import messaging


# #######################    DATA MODEL    ####################### #

class Transactor:
    """
    NetBill entity
    """

    def __init__(self):
        self.identifier = config.TRANSACTOR_ID
        self.private_key, self.public_key = cryptography.generate_private_public_key_pair()
        self.public_keychain = {}


# ####################### ENTITY ELEMENTS  ####################### #
app = Flask(__name__)
data = Transactor()


# #######################  SERVER UTILITY  ####################### #

def run_server(address):
    host, port = address.split(':')
    app.run(host=host, port=port)


# ####################### SERVICE METHODS  ####################### #


def transaction_process():
    pass


def add_customer():
    pass


def add_merchant():
    pass


def initialize_transaction(self, customer_id, merchant_id, use_psudonym):
    if not use_psudonym:
        self.share_public_keys(customer_id, merchant_id)


def generate_ticket():
    pass


def generate_psudonym_ticket():
    pass


def share_public_keys(merchant_id, customer_id):
    pass


@app.route(slash(static.GET_CONTACT_INFO), methods=['POST'])
def get_contact_info():
    logger.log_access(request)
    contact_info = SEP.join([data.identifier, data.public_key])
    return contact_info, 200


@app.route(slash(static.CREATE_PSUDONYM), methods=['POST'])
def create_psudonym():
    logger.log_access(request)
    message = messaging.get_request_data(request)
    two_layer_enc_message, encrypted_key, nonce, timestamp, signature = message.split(SEP)
    plain_message = cryptography.two_layer_sym_asym_decode(SEP.join([two_layer_enc_message, encrypted_key]),
                                                           data.private_key)
    true_identity, merchant_identifier, timestamp, offered_symmetric_key, type_ = plain_message.split(SEP)

    warn_message = None

    if true_identity not in data.public_keychain:
        warn_message = 'client unknown'
    elif merchant_identifier not in data.public_keychain:
        warn_message = 'merchant unknown'
    elif not cryptography.verify_clear_signature(message, data.public_keychain[true_identity]):
        warn_message = 'clear signature not verified.'

    elif type_ not in [PsudonymTypes.PER_MERCHANT.value, PsudonymTypes.PER_SESSION.value]:
        warn_message = 'invalid psudonym type.'
    elif type_ == PsudonymTypes.PER_SESSION:
        warn_message = 'psudonym type not implemented.'

        # todo check for timestamp

    if warn_message is not None:
        logger.log_warn(warn_message)
        return warn_message, 403

    psudonym_symmetric_key = cryptography.generate_symmetric_key()

    psudonym = cryptography.generate_random_identity()
    timestamp = cryptography.get_timestamp()  # todo move get_timestamp somewhere else?

    psudonym_ticket = SEP.join([psudonym, merchant_identifier, timestamp, psudonym_symmetric_key])
    psudonym_ticket_two_layer_enc = \
        cryptography.two_layer_sym_asym_encode(psudonym_ticket, data.public_keychain[merchant_identifier])
    psudonym_ticket_two_layer_enc_clear_signed = cryptography.clear_sign(psudonym_ticket_two_layer_enc,
                                                                         data.private_key)

    psudonym_receipt = SEP.join([true_identity, merchant_identifier, psudonym, timestamp])

    psudonym_receipt_clear_signed = cryptography.clear_sign(psudonym_receipt, data.private_key)

    final_message_to_encrypt = SEP.join([
        psudonym_symmetric_key,
        psudonym_ticket_two_layer_enc_clear_signed,
        psudonym_receipt_clear_signed
    ])

    final_encrypted_message = cryptography.encrypt_sym(final_message_to_encrypt, offered_symmetric_key)

    return final_encrypted_message, 200


@app.route(slash(static.REGISTER_CLIENT), methods=['POST'])
def register_client():
    logger.log_access(request)
    message_enc = messaging.get_request_data(request)
    message = cryptography.two_layer_sym_asym_decode(message_enc, data.private_key)

    client_identifier, client_public_key, transactor_identifier = message.split(SEP)

    if transactor_identifier != data.identifier:
        warn_message = 'invalid transactor identifier.'
        logger.log_warn(warn_message)
        return warn_message, 403

    if client_identifier in data.public_keychain:
        logger.log_info('client exists. updating.')

    data.public_keychain[client_identifier] = client_public_key

    return 'client registered', 200


@app.route(slash(static.REGISTER_MERCHANT), methods=['POST'])
def register_merchant():
    logger.log_access(request)
    message_enc = messaging.get_request_data(request)
    message = cryptography.two_layer_sym_asym_decode(message_enc, data.private_key)

    merchant_identifier, merchant_public_key, transactor_identifier = message.split(SEP)

    if transactor_identifier != data.identifier:
        warn_message = 'invalid transactor identifier.'
        logger.log_warn(warn_message)
        return warn_message, 403

    if merchant_identifier in data.public_keychain:
        logger.log_info('merchant exists. updating.')

    data.public_keychain[merchant_identifier] = merchant_public_key

    return 'merchant registered', 200


if __name__ == '__main__':
    try:
        run_server(config.ADDRESS_BOOK[config.TRANSACTOR_ID])
    except KeyboardInterrupt:
        logger.log_info('keyboard interrupt, exiting...')
        exit(0)
