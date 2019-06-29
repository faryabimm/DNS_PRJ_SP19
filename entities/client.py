from flask import Flask

import configuration as config
import static
from configuration import MESSAGE_SEPARATOR as SEP
from entities.principal import Principal
from entities.psudonym_types import PsudonymTypes
from utils import cryptography, messaging
from utils import logger


# #######################    DATA MODEL    ####################### #


class Client(Principal):
    def __init__(self, identifier):
        super().__init__(identifier)
        self.merchant_tickets = {}


# ####################### ENTITY ELEMENTS  ####################### #
app = Flask(__name__)
data = Client(b'client')


# #######################  SERVER UTILITY  ####################### #

# todo delete :?

def run_server(address):
    host, port = address.split(':')
    app.run(host=host, port=port)


# ####################### SERVICE METHODS  ####################### #

def get_arbitrary_merchant_ticket(merchant_id, psudonymous=False):
    for record in data.merchant_tickets:
        if record[0] == merchant_id and ((record[1] != data.identifier) == psudonymous):
            return data.merchant_tickets[record][0], data.merchant_tickets[record][0], record[1]

    logger.log_info('ticket not found for merchant: `{}`, psudonymous: `{}`'.format(merchant_id, psudonymous))
    return None, None, None


def get_merchant_ticket(merchant_id, identity):
    for record in data.merchant_tickets:
        # (merchant_id, identity): (ticket, symmetric_key)
        if record[0] == merchant_id and record[1] == identity:
            return data.merchant_tickets[record][0], data.merchant_tickets[record][0], record[1]

    logger.log_info('ticket not found for merchant: `{}`, identity: `{}`'.format(merchant_id, identity))
    return None, None, None


def add_merchant_ticket_and_identity(merchant_id, identity, ticket, timestamp=None):
    if timestamp is None:
        timestamp = cryptography.get_timestamp()

    if (merchant_id, identity) in data.merchant_tickets:
        logger.log_info('ticket exists. updating.')

    data.merchant_tickets[(merchant_id, identity)] = (ticket, timestamp)


def price_request():
    pass


def goods_request():
    pass


def payment_request():
    pass


def request_psudonym_ticket_request(merchant_id):
    k1 = cryptography.generate_symmetric_key()
    true_identity = data.identifier
    m = merchant_id
    timestamp = cryptography.get_timestamp()
    type_ = PsudonymTypes.PER_MERCHANT.value

    message = SEP.join([true_identity, m, timestamp, k1, type_])

    _, transactor_public_key = data.get_transactor_contact()
    encrypted_message = cryptography.two_layer_sym_asym_encode(message_bytes=message,
                                                               public_key_bytes=transactor_public_key)
    clear_signed_encrypted_message = cryptography.clear_sign(encrypted_message, data.private_key)

    response_enc = messaging.transmit_message_and_get_response(config.ADDRESS_BOOK[config.TRANSACTOR_ID],
                                                               static.CREATE_PSUDONYM,
                                                               clear_signed_encrypted_message)

    parts = cryptography.decrypt_sym(response_enc, k1).split(SEP)

    psudonym_sym_key = parts[0]
    merchant_psudonym_clear_signed_ticket = SEP.join(parts[1:6])
    psudonym_receipt_clear_signed = SEP.join(parts[6:])

    _, transactor_public_key = data.get_transactor_contact()
    _, verified = cryptography.verify_clear_signature(
        merchant_psudonym_clear_signed_ticket,
        transactor_public_key)
    if not verified:
        logger.log_warn('psudonymous merchant ticket signature not verified.')
    psudonym_receipt, verified = cryptography.verify_clear_signature(psudonym_receipt_clear_signed,
                                                                     transactor_public_key)
    if not verified:
        logger.log_warn('psudonymous receipt signature not verified.')

    receipt_true_identity, receipt_merchant, receipt_psudonymous_identity, receipt_timestamp = psudonym_receipt.split(
        SEP)

    if receipt_true_identity != true_identity:
        logger.log_warn('true identity differs in psudonym receipt.')
    if receipt_merchant != merchant_id:
        logger.log_warn('merchant identity differs in psudonym receipt.')

        # todo check timestamps

    logger.log_info('got psudonym merchant ticket request with identity `{}` for client `{}` on merchant `{}`'.format(
        receipt_psudonymous_identity,
        true_identity,
        merchant_id
    ))

    return psudonym_sym_key, receipt_psudonymous_identity, merchant_psudonym_clear_signed_ticket


def register_on_transactor():
    transactor_id, transactor_public_key = data.get_transactor_contact()
    message = SEP.join([data.identifier, data.public_key, transactor_id])
    message_encrypted = cryptography.two_layer_sym_asym_encode(message, transactor_public_key)
    messaging.transmit_message_and_get_response(config.ADDRESS_BOOK[config.TRANSACTOR_ID], static.REGISTER_CLIENT,
                                                message_encrypted)


def __create_identity_ticket_request(merchant_id):
    if merchant_id not in data.public_keychain:
        logger.log_warn('merchant id', merchant_id, 'not found.')
        return

    identity = data.identifier
    timestamp = cryptography.get_timestamp()
    symmetric_key = cryptography.generate_symmetric_key()

    message_to_encrypt = SEP.join([identity, merchant_id, timestamp, symmetric_key])
    message_encrypted = cryptography.two_layer_sym_asym_encode(message_to_encrypt, data.public_keychain[merchant_id])
    message_encrypted_signed = cryptography.clear_sign(message_encrypted, data.private_key)

    return symmetric_key, message_encrypted_signed


def get_ticket_and_key(merchant_id, psudonymous):
    ticket, access_symmetric_key, identity = get_arbitrary_merchant_ticket(merchant_id, psudonymous)

    if ticket is not None:
        return ticket, access_symmetric_key, identity

    if psudonymous:
        symmetric_key, identity, ticket_request = request_psudonym_ticket_request(merchant_id)
    else:
        symmetric_key, ticket_request = __create_identity_ticket_request(merchant_id)
        identity = data.identifier

    response_enc = messaging.transmit_message_and_get_response(config.ADDRESS_BOOK[merchant_id], static.CREATE_TICKET,
                                                               ticket_request)

    response = cryptography.decrypt_sym(response_enc, symmetric_key)
    ticket, access_symmetric_key = response.split(SEP)

    data.merchant_tickets[(merchant_id, identity)] = (ticket, access_symmetric_key)

    return ticket, access_symmetric_key, identity


def main():
    data.get_transactor_contact()
    register_on_transactor()
    data.get_server_contact_info(config.MERCHANT_ID)
    get_ticket_and_key(config.MERCHANT_ID, psudonymous=False)
    get_ticket_and_key(config.MERCHANT_ID, psudonymous=True)
    pass


if __name__ == '__main__':
    main()
