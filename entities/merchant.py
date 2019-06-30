from flask import Flask, request

import configuration as config
import static
from configuration import MESSAGE_SEPARATOR as SEP
from entities.principal import Principal
from static import slash_contain as slash
# #######################    DATA MODEL    ####################### #
from utils import messaging, cryptography, logger

BID_PRICE_RATIO_THRESHOLD = 0.8


class Merchant(Principal):
    def __init__(self, identifier):
        super().__init__(identifier)
        self.epoid_serial_key_map = {}


# ####################### ENTITY ELEMENTS  ####################### #
app = Flask(__name__)
data = Merchant(config.MERCHANT_ID)


# #######################  SERVER UTILITY  ####################### #

def run_server(address):
    host, port = address.split(':')
    app.run(host=host, port=port)


# ####################### SERVICE METHODS  ####################### #


def price_quote(self):
    pass


def goods_deliver(self):
    pass


def transaction_request(self):
    pass


def forward_receipt(self):
    pass


def register_on_transactor():
    transactor_id, transactor_public_key = data.get_transactor_contact()
    message = SEP.join([data.identifier, data.public_key, transactor_id])
    message_encrypted = cryptography.two_layer_sym_asym_encode(message, transactor_public_key)
    messaging.transmit_message_and_get_response(config.ADDRESS_BOOK[config.TRANSACTOR_ID], static.REGISTER_MERCHANT,
                                                message_encrypted)


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
    decrypted_data = cryptography.two_layer_sym_asym_decode(encrypted_data, data.private_key)

    client_identity, merchant_id, timestamp, symmetric_key = decrypted_data.split(SEP)

    if data.identifier != merchant_id:
        warn_message = 'merchant id does not match.'
        logger.log_warn(warn_message)
        return warn_message, 403

    # todo check timestamp

    client_access_symmetric_key = cryptography.generate_symmetric_key()
    client_address = request.remote_addr.encode('utf-8')
    ticket_start_timestamp, ticket_end_timestamp = cryptography.get_ticket_life_span()
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


@app.route(slash(static.REQUEST_PRICE), methods=['POST'])
def request_price():
    logger.log_access(request)
    message = messaging.get_request_data(request)
    ticket, price_request_enc = message.split(SEP)
    sym_key, client_identity, _, _, _ = cryptography.open_merchant_ticket(ticket, data.private_key)

    # todo check client address, start, end timestamp of ticket

    price_request = cryptography.decrypt_sym(price_request_enc, sym_key)

    parts = price_request.split(SEP)

    transaction_id = parts[-1]
    bid = parts[-3]
    product_request_data = parts[-4]
    credentials = parts[:-4]

    if credentials == b'':
        credentials = None
    if transaction_id == b'':
        transaction_id = cryptography.generate_random_transaction_id()
    if bid == b'':
        bid = None
    # todo check credentials if present

    product_id = __get_product_id_from_product_request_data(product_request_data)

    if product_id not in config.PRODUCT_SHELF[data.identifier]:
        warn_message = 'product `{}` is not present in shelf for merchant `{}`'.format(product_id, data.identifier)
        logger.log_warn(warn_message)
        return warn_message, 403

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
    sym_key, _, _, _, _ = cryptography.open_merchant_ticket(ticket, data.private_key)

    # todo check client address, start, end timestamp of ticket

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

    epoid_serial_number = cryptography.generate_epoid_serial_number()

    data.epoid_serial_key_map[epoid_serial_number] = goods_delivery_key

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


def initialize():
    data.get_transactor_contact()
    register_on_transactor()


if __name__ == '__main__':
    try:
        initialize()
        run_server(config.ADDRESS_BOOK[config.MERCHANT_ID])
    except KeyboardInterrupt:
        logger.log_info('keyboard interrupt, exiting...')
        exit(0)
