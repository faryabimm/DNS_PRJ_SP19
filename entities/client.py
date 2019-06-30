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
        self.tickets = {}


# ####################### ENTITY ELEMENTS  ####################### #
app = Flask(__name__)
data = Client(b'client')


# #######################  SERVER UTILITY  ####################### #

# todo delete :?

def run_server(address):
    host, port = address.split(':')
    app.run(host=host, port=port)


# ####################### SERVICE METHODS  ####################### #

def get_arbitrary_ticket(merchant_id, psudonymous=False):
    for record in data.tickets:
        if record[0] == merchant_id and ((record[1] != data.identifier) == psudonymous):
            return data.tickets[record][0], data.tickets[record][1], record[1]

    logger.log_info('ticket not found for merchant: `{}`, psudonymous: `{}`'.format(merchant_id, psudonymous))
    return None, None, None


def get_merchant_ticket(merchant_id, identity):
    for record in data.tickets:
        # (merchant_id, identity): (ticket, symmetric_key)
        if record[0] == merchant_id and record[1] == identity:
            return data.tickets[record][0], data.tickets[record][1], record[1]

    logger.log_info('ticket not found for merchant: `{}`, identity: `{}`'.format(merchant_id, identity))
    return None, None, None


def add_merchant_ticket_and_identity(merchant_id, identity, ticket, timestamp=None):
    if timestamp is None:
        timestamp = cryptography.get_timestamp()

    if (merchant_id, identity) in data.tickets:
        logger.log_info('ticket exists. updating.')

    data.tickets[(merchant_id, identity)] = (ticket, timestamp)


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
    response = messaging.transmit_message_and_get_response(config.ADDRESS_BOOK[config.TRANSACTOR_ID],
                                                           static.REGISTER_CLIENT,
                                                           message_encrypted)

    response_plain = cryptography.two_layer_sym_asym_decode(response, data.private_key)
    account_number, nonce = response_plain.split(SEP)
    data.account = (account_number, nonce)


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


def get_ticket_key_id(server_id, psudonymous=False):
    ticket, access_symmetric_key, identity = get_arbitrary_ticket(server_id, psudonymous)

    if server_id == config.TRANSACTOR_ID and psudonymous:
        logger.log_warn('cannot obtain psudonymous ticket for transactor. obtaining normal ticket.')
        psudonymous = False

    if ticket is not None:
        return ticket, access_symmetric_key, identity

    if psudonymous:
        symmetric_key, identity, ticket_request = request_psudonym_ticket_request(server_id)
    else:
        symmetric_key, ticket_request = __create_identity_ticket_request(server_id)
        identity = data.identifier

    response_enc = messaging.transmit_message_and_get_response(config.ADDRESS_BOOK[server_id], static.CREATE_TICKET,
                                                               ticket_request)

    response = cryptography.decrypt_sym(response_enc, symmetric_key)
    ticket, access_symmetric_key = response.split(SEP)

    data.tickets[(server_id, identity)] = (ticket, access_symmetric_key)

    return ticket, access_symmetric_key, identity


def request_price(merchant_id, psudonymous, product_request_data=None, bid=None, credentials=None, transaction_id=None):
    ticket, sym_key, _ = get_ticket_key_id(merchant_id, psudonymous)

    if transaction_id is not None and transaction_id not in data.transaction_context:
        logger.log_warn('must not provide `transaction_id` in initial transaction interaction')
        return

    if transaction_id is None and product_request_data is None:
        logger.log_warn('must provide `product_request_data` in initial transaction interaction')
        return

    if transaction_id is not None and product_request_data is not None and \
            data.transaction_context[transaction_id]['product_request_data'] != product_request_data:
        logger.log_warn('cannot change `product_request_data` after initial transaction interaction')
        return

    if bid is not None and not bid.endswith(config.CURRENCY):
        logger.log_warn('bid should end with currency postfix `{}`'.format(config.CURRENCY))
        return

    if bid is not None and not cryptography.is_number_valued_bytes(bid[:-len(config.CURRENCY)].strip()):
        logger.log_warn('bid should have a proper numeric form')
        return

    if bid is not None:
        num_part = bid[:-len(config.CURRENCY)].strip()
        if float(num_part) == int(float(num_part)):
            bid = bytes(str(int(num_part)), encoding='utf-8') + config.CURRENCY
        else:
            bid = bytes(str(float(num_part)), encoding='utf-8') + config.CURRENCY

    if transaction_id is not None:
        product_request_data = data.transaction_context[transaction_id]['product_request_data']
    # todo group membership
    if credentials is None:
        credentials = b''
    request_flags = b''
    if bid is None:
        message_body_bid = b''
    else:
        message_body_bid = bid

    if transaction_id is None:
        transaction_id = cryptography.generate_random_transaction_id()

    price_request_plain = SEP.join([credentials, product_request_data, message_body_bid, request_flags, transaction_id])
    price_request_enc = cryptography.encrypt_sym(price_request_plain, sym_key)
    message = SEP.join([ticket, price_request_enc])

    response = messaging.transmit_message_and_get_response(config.ADDRESS_BOOK[merchant_id], static.REQUEST_PRICE,
                                                           message)
    response_plain = cryptography.decrypt_sym(response, sym_key)
    product_id, price, _, response_transaction_id = response_plain.split(SEP)

    if transaction_id != response_transaction_id:
        logger.log_warn('`transaction_id` mismatch')

    data.update_transaction_context(transaction_id, product_request_data, product_id, bid, price, merchant_id)

    return product_id, price, transaction_id


def request_goods(merchant_id, psudonymous, transaction_id):
    if transaction_id not in data.transaction_context:
        logger.log_warn('`transaction_id` not found')

    ticket, sym_key, _ = get_ticket_key_id(merchant_id, psudonymous)

    goods_request_enc = cryptography.encrypt_sym(transaction_id, sym_key)
    message = SEP.join([ticket, goods_request_enc])

    response = messaging.transmit_message_and_get_response(config.ADDRESS_BOOK[merchant_id], static.REQUEST_GOODS,
                                                           message)
    enc_product, enc_receipt = response.split(SEP)

    receipt = cryptography.decrypt_sym(enc_receipt, sym_key)
    enc_product_checksum, receipt_merchant_id, epoid_serial_number = receipt.split(SEP)

    if merchant_id != receipt_merchant_id:
        logger.log_warn('`merchant_id` mismatch')
        return

    if enc_product_checksum != cryptography.cryptographic_checksum(enc_product):
        logger.log_warn('encrypted product checksum mismatch.')
        return

    timestamp = cryptography.get_timestamp()
    epoid_plain = SEP.join([merchant_id, timestamp, epoid_serial_number])

    return transaction_id, enc_product, epoid_plain


def send_signed_epo(merchant_id, psudonymous, transaction_id, enc_product, epoid_plain):
    merchant_ticket, merchant_sym_key, identity = get_ticket_key_id(merchant_id, psudonymous)

    if transaction_id not in data.transaction_context:
        logger.log_warn('transaction not found.')
        return

    product_id = data.transaction_context[transaction_id]['product_id']
    product_request_data = data.transaction_context[transaction_id]['product_request_data']
    price = data.transaction_context[transaction_id]['bid']

    enc_product_checksum = cryptography.cryptographic_checksum(enc_product)
    product_request_data_checksum = cryptography.cryptographic_checksum(product_request_data)
    account_data_checksum = cryptography.cryptographic_checksum(SEP.join(data.account))

    transactor_ticket, transactor_sym_key, _ = get_ticket_key_id(config.TRANSACTOR_ID)

    authorization = b''  # todo checkup correctness
    client_memo = b''

    order_for_transactor_plain = SEP.join([
        authorization,
        SEP.join(data.account),
        client_memo
    ])

    order_for_transactor = cryptography.encrypt_sym(order_for_transactor_plain, transactor_sym_key)

    epo_plain = SEP.join([
        identity,
        product_id,
        price,
        merchant_id,
        enc_product_checksum,
        product_request_data_checksum,
        account_data_checksum,
        epoid_plain,
        transactor_ticket,
        order_for_transactor
    ])

    epo_clear_signed = cryptography.clear_sign(epo_plain, data.private_key)

    epo_clear_signed_enc = cryptography.encrypt_sym(epo_clear_signed, merchant_sym_key)

    message = SEP.join([merchant_ticket, epo_clear_signed_enc])

    response = messaging.transmit_message_and_get_response(config.ADDRESS_BOOK[merchant_id], static.SUBMIT_SIGNED_EPO,
                                                           message)

    response_plain = cryptography.decrypt_sym(response, merchant_sym_key)

    parts = response_plain.split(SEP)

    client_receipt = parts[-1]
    transaction_receipt_dsa_signed = SEP.join(parts[:-1])

    transaction_receipt, verified = cryptography.dsa_verify(transaction_receipt_dsa_signed,
                                                            data.transactor_dsa_public_key)

    if not verified:
        warn_message = 'transaction receipt not verified'
        logger.log_warn(warn_message)
        return warn_message, 403

    parts = transaction_receipt.split(SEP)

    receipt_result = parts[0]
    receipt_client_identity = parts[1]
    receipt_price = parts[2]
    receipt_product_id = parts[3]
    receipt_merchant_id = parts[4]
    receipt_product_key = parts[5]
    receipt_epoid = SEP.join(parts[6:])

    transaction_context = data.transaction_context[transaction_id]

    warn_message = None
    if receipt_client_identity != data.identifier:
        warn_message = '`client_id` mismatch'
    elif receipt_price != transaction_context['bid']:
        warn_message = 'paid `price` mismatch'
    elif receipt_product_id != product_id:
        warn_message = '`product_id` mismatch'
    elif receipt_merchant_id != merchant_id:
        warn_message = '`merchant_id` mismatch'
    elif receipt_epoid != epoid_plain:
        warn_message = '`epoid` mismatch'

    if warn_message is not None:
        logger.log_warn(warn_message)
        return

    client_receipt_plain = cryptography.decrypt_sym(client_receipt, transactor_sym_key)
    parts = client_receipt_plain.split(SEP)

    flags = parts[-1]
    balance = parts[-2]
    client_account = parts[-3]
    client_receipt_epoid = SEP.join(parts[:-3])

    warn_message = None
    if client_receipt_epoid != epoid_plain:
        warn_message = '`epoid` mismatch'
    if client_account != data.account[0]:
        warn_message = 'client `account` mismatch'

    if warn_message is not None:
        logger.log_warn(warn_message)
        return

    return receipt_result, receipt_product_key, balance


def main():
    data.get_transactor_contact()
    register_on_transactor()
    data.get_server_contact_info(config.MERCHANT_ID)
    # get_ticket_key_id(config.MERCHANT_ID, psudonymous=False)
    # get_ticket_key_id(config.MERCHANT_ID, psudonymous=True)

    product_id, price, transaction_id = request_price(config.MERCHANT_ID, False, product_request_data=b'sneakers',
                                                      bid=b'67.5USD')
    transaction_id, enc_goods, epoid_plain = request_goods(config.MERCHANT_ID, False, transaction_id=transaction_id)

    transaction_result, product_key, balance = send_signed_epo(config.MERCHANT_ID, False, transaction_id, enc_goods,
                                                               epoid_plain)

    product = cryptography.decrypt_sym(enc_goods, product_key)

    pass


if __name__ == '__main__':
    main()
