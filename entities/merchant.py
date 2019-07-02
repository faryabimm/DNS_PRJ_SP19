from flask import Flask, request

import configuration as config
import static
from configuration import MESSAGE_SEPARATOR as SEP
from entities.principal import Principal
from static import slash_contain as slash
# #######################    DATA MODEL    ####################### #
from utils import messaging, cryptography, logger, generator

BID_PRICE_RATIO_THRESHOLD = 0.8
DISCOUNTED_PRICE_RATIO = 0.8


class Merchant(Principal):
    def __init__(self, identifier):
        super().__init__(identifier)
        self.epoid_serial_key_map = {}
        self.tickets = {}
        self.epoid_serial_transaction_id_map = {}
        self.trusted_groups = [config.GROUP_ID]


# ####################### ENTITY ELEMENTS  ####################### #
app = Flask(__name__)
data = Merchant(config.MERCHANT_ID)


# #######################  SERVER UTILITY  ####################### #

def run_server(address):
    host, port = address.split(':')
    app.run(host=host, port=port)


# ####################### SERVICE METHODS  ####################### #

def register_on_transactor():
    transactor_id, transactor_public_key = data.get_transactor_contact()
    message = SEP.join([data.identifier, data.public_key, transactor_id])
    message_encrypted = cryptography.two_layer_sym_asym_encrypt(message, transactor_public_key)
    response = messaging.transmit_message_and_get_response(config.ADDRESS_BOOK[config.TRANSACTOR_ID],
                                                           static.REGISTER_MERCHANT,
                                                           message_encrypted)
    response_plain = cryptography.two_layer_sym_asym_decrypt(response, data.private_key)
    account_number, nonce = response_plain.split(SEP)
    data.account = (account_number, nonce)


@app.route(slash(static.GET_CONTACT_INFO), methods=['POST'])
def get_contact_info():
    logger.log_access(request)
    contact_info = SEP.join([data.identifier, data.public_key])
    return contact_info, 200


@app.route(slash(static.CREATE_TICKET), methods=['POST'])
def create_ticket():
    logger.log_access(request)
    message = messaging.get_request_data(request)
    encrypted_data = cryptography.strip_clear_signed_message(message)
    decrypted_data = cryptography.two_layer_sym_asym_decrypt(encrypted_data, data.private_key)

    client_identity, merchant_id, timestamp, symmetric_key = decrypted_data.split(SEP)

    if data.identifier != merchant_id:
        warn_message = 'merchant id does not match.'
        logger.log_warn(warn_message)
        return warn_message, 403

    client_access_symmetric_key = cryptography.generate_symmetric_key()
    client_address = request.remote_addr.encode('utf-8')
    ticket_start_timestamp, ticket_end_timestamp = generator.get_ticket_life_span()
    ticket_unencrypted = SEP.join([
        client_access_symmetric_key,
        client_identity,
        client_address,
        ticket_start_timestamp,
        ticket_end_timestamp
    ])

    ticket = cryptography.encrypt_asym(ticket_unencrypted, data.public_key)

    response = cryptography.encrypt_sym(SEP.join([
        ticket,
        client_access_symmetric_key
    ]), symmetric_key)

    logger.log_info('generated access ticket and key for client id `{}`'.format(client_identity))

    return response, 200


def __calculate_discounted_price(group_id, detail, credentials_client_identity, account_checksum, product_id):
    # implement custom discount logic
    real_price = config.PRODUCT_SHELF[data.identifier][product_id] + config.CURRENCY
    real_price_num = generator.get_price_number(real_price)
    discounted_price_num = real_price_num * DISCOUNTED_PRICE_RATIO
    discounted_price = generator.get_price_bytes(discounted_price_num)

    return discounted_price


@app.route(slash(static.REQUEST_PRICE), methods=['POST'])
def request_price():
    logger.log_access(request)
    message = messaging.get_request_data(request)
    ticket, price_request_enc = message.split(SEP)
    sym_key, client_identity, _, _, _ = cryptography.open_ticket(ticket, data.private_key)

    price_request = cryptography.decrypt_sym(price_request_enc, sym_key)

    parts = price_request.split(SEP)

    transaction_id = parts[-1]
    bid = parts[-3]
    product_request_data = parts[-4]
    credentials = SEP.join(parts[:-4])

    if credentials == b'':
        credentials = None
    if transaction_id == b'':
        transaction_id = generator.generate_random_transaction_id()
    if bid == b'':
        bid = None

    product_id = __get_product_id_from_product_request_data(product_request_data)

    if product_id not in config.PRODUCT_SHELF[data.identifier]:
        warn_message = 'product `{}` is not present in shelf for merchant `{}`'.format(product_id, data.identifier)
        logger.log_warn(warn_message)
        return warn_message, 403

    if credentials is not None:
        credentials_message = cryptography.strip_clear_signed_message(credentials)
        group_id, detail, credentials_client_identity, account_checksum, timestamp = credentials_message.split(SEP)

        if group_id not in data.trusted_groups:
            warn_message = 'unknown group'
            logger.log_warn(warn_message)
            return warn_message, 403

        _, verified = cryptography.verify_clear_signature(credentials, data.public_keychain[group_id])

        if not verified:
            warn_message = 'group credentials not verified'
            logger.log_warn(warn_message)
            return warn_message, 403

        price = __calculate_discounted_price(group_id, detail, credentials_client_identity, account_checksum,
                                             product_id)
    else:
        price = config.PRODUCT_SHELF[data.identifier][product_id] + config.CURRENCY

    request_flags = b''

    response_plain = SEP.join([product_id, price, request_flags, transaction_id])
    response = cryptography.encrypt_sym(response_plain, sym_key)

    data.update_transaction_context(transaction_id, product_request_data, product_id, bid, price, client_identity)

    return response, 200


@app.route(slash(static.REQUEST_GOODS), methods=['POST'])
def request_goods():
    logger.log_access(request)
    message = messaging.get_request_data(request)
    ticket, goods_request_enc = message.split(SEP)
    sym_key, _, _, _, _ = cryptography.open_ticket(ticket, data.private_key)

    transaction_id = cryptography.decrypt_sym(goods_request_enc, sym_key)
    transaction_context = data.transaction_context[transaction_id]

    warn_message = None
    if transaction_id not in data.transaction_context:
        warn_message = 'invalid `transaction_id`'
    elif not should_proceed_transaction(transaction_context):
        warn_message = 'transaction not accepted by merchant'

    if warn_message is not None:
        logger.log_warn(warn_message)
        return warn_message, 403

    goods_delivery_key = cryptography.generate_symmetric_key()

    product = __get_product(product_id=transaction_context['product_id'])
    product_enc = cryptography.encrypt_sym(product, goods_delivery_key)
    product_enc_checksum = cryptography.cryptographic_checksum(product_enc)

    epoid_serial_number = generator.generate_epoid_serial_number()

    data.epoid_serial_key_map[epoid_serial_number] = goods_delivery_key
    data.epoid_serial_transaction_id_map[epoid_serial_number] = transaction_id

    merchant_id = data.identifier

    receipt_plain = SEP.join([product_enc_checksum, merchant_id, epoid_serial_number])
    receipt_enc = cryptography.encrypt_sym(receipt_plain, sym_key)

    response = SEP.join([product_enc, receipt_enc])
    return response, 200


def should_proceed_transaction(transaction_context):
    if transaction_context['bid'] is None:
        logger.log_warn('there is no `bid` set for transaction')
        return False

    bid_value = float(transaction_context['bid'][:-len(config.CURRENCY)])
    price_value = float(transaction_context['price'][:-len(config.CURRENCY)])

    # custom, complex logic can be implemented here

    if bid_value / price_value >= BID_PRICE_RATIO_THRESHOLD:
        return True

    return False


def __get_product_id_from_product_request_data(product_request_data):
    # can implement complex NLP logic here.
    return product_request_data


def __get_product(product_id):
    # implement logic to load the resource and return it. this is just a stub.
    return product_id


@app.route(slash(static.SUBMIT_SIGNED_EPO), methods=['POST'])
def submit_signed_epo():
    logger.log_access(request)
    message = messaging.get_request_data(request)
    ticket, signed_epo_enc = message.split(SEP)
    client_sym_key, _, _, _, _ = cryptography.open_ticket(ticket, data.private_key)

    signed_epo = cryptography.decrypt_sym(signed_epo_enc, client_sym_key)
    epo = cryptography.strip_clear_signed_message(signed_epo)
    parts = epo.split(SEP)

    client_identity = parts[0]
    product_id = parts[1]
    price_to_pay = parts[2]
    merchant_id = parts[3]
    enc_product_checksum = parts[4]
    product_request_data_checksum = parts[5]
    account_data_checksum = parts[6]
    epoid_plain = SEP.join(parts[7:10])
    client_transactor_ticket = parts[10]
    order_for_transactor = parts[11]

    epoid_merchant_id, epoid_timestamp, epoid_serial_number = epoid_plain.split(SEP)

    warn_message = None
    if epoid_merchant_id != data.identifier or merchant_id != data.identifier:
        warn_message = '`merchant_id` mismatch'
    elif epoid_serial_number not in data.epoid_serial_key_map:
        warn_message = 'invalid `epo_id_serial_number`'

    if warn_message is not None:
        logger.log_warn(warn_message)
        return warn_message, 403

    product_key = data.epoid_serial_key_map[epoid_serial_number]
    transaction_id = data.epoid_serial_transaction_id_map[epoid_serial_number]
    transaction_context = data.transaction_context[transaction_id]

    warn_message = None
    if transaction_context['peer_id'] != client_identity:
        warn_message = '`client_id` mismatch'
    if cryptography.cryptographic_checksum(
            transaction_context['product_request_data']) != product_request_data_checksum:
        warn_message = 'corrupted `product_request_data`'
    if transaction_context['product_id'] != product_id:
        warn_message = '`product_id` mismatch'

    if warn_message is not None:
        logger.log_warn(warn_message)
        return warn_message, 403

    transactor_ticket, transactor_sym_key = get_ticket_key_id(config.TRANSACTOR_ID)

    merchant_memo = b''

    endorsed_signed_epo_plain = SEP.join([
        signed_epo,
        data.account[0],
        merchant_memo,
        product_key
    ])

    endorsed_signed_epo_plain_signed = cryptography.clear_sign(endorsed_signed_epo_plain, data.private_key)

    endorsed_signed_epo_plain_signed_encrypted = cryptography.encrypt_sym(endorsed_signed_epo_plain_signed,
                                                                          transactor_sym_key)

    message_to_transactor = SEP.join([transactor_ticket, endorsed_signed_epo_plain_signed_encrypted])

    transactor_response = messaging.transmit_message_and_get_response(config.ADDRESS_BOOK[config.TRANSACTOR_ID],
                                                                      static.SUBMIT_ENDORSED_SIGNED_EPO,
                                                                      message_to_transactor)

    transactor_response_plain = cryptography.decrypt_sym(transactor_response, transactor_sym_key)

    parts = transactor_response_plain.split(SEP)

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

    warn_message = None
    if receipt_client_identity != client_identity:
        warn_message = '`client_id` mismatch'
    elif receipt_price != transaction_context['bid']:
        warn_message = 'paid `price` mismatch'
    elif receipt_product_id != product_id:
        warn_message = '`product_id` mismatch'
    elif receipt_merchant_id != merchant_id or receipt_merchant_id != data.identifier:
        warn_message = '`merchant_id` mismatch'
    elif receipt_product_key != product_key:
        warn_message = '`product_key` mismatch'
    elif receipt_epoid != epoid_plain:
        warn_message = '`epoid` mismatch'

    if warn_message is not None:
        logger.log_warn(warn_message)
        return warn_message, 403

    return cryptography.encrypt_sym(transactor_response_plain, client_sym_key), 200


def get_arbitrary_ticket(merchant_id):
    for record in data.tickets:
        if record == merchant_id:
            return data.tickets[record]
    return None, None


def get_ticket_key_id(server_id):
    ticket, access_symmetric_key = get_arbitrary_ticket(server_id)

    if ticket is not None:
        return ticket, access_symmetric_key

    symmetric_key, ticket_request = __create_identity_ticket_request(server_id)

    response_enc = messaging.transmit_message_and_get_response(config.ADDRESS_BOOK[server_id], static.CREATE_TICKET,
                                                               ticket_request)

    response = cryptography.decrypt_sym(response_enc, symmetric_key)
    ticket, access_symmetric_key = response.split(SEP)

    data.tickets[server_id] = (ticket, access_symmetric_key)

    return ticket, access_symmetric_key


def __create_identity_ticket_request(merchant_id):
    if merchant_id not in data.public_keychain:
        logger.log_warn('merchant id', merchant_id, 'not found.')
        return

    identity = data.identifier
    timestamp = generator.get_timestamp()
    symmetric_key = cryptography.generate_symmetric_key()

    message_to_encrypt = SEP.join([identity, merchant_id, timestamp, symmetric_key])
    message_encrypted = cryptography.two_layer_sym_asym_encrypt(message_to_encrypt, data.public_keychain[merchant_id])
    message_encrypted_signed = cryptography.clear_sign(message_encrypted, data.private_key)

    return symmetric_key, message_encrypted_signed


def initialize():
    data.get_transactor_contact()
    register_on_transactor()
    for group_id in data.trusted_groups:
        data.get_server_contact_info(group_id)


if __name__ == '__main__':
    try:
        initialize()
        run_server(config.ADDRESS_BOOK[config.MERCHANT_ID])
    except KeyboardInterrupt:
        logger.log_info('keyboard interrupt, exiting...')
        exit(0)
