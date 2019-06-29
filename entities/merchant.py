from flask import Flask, request

import configuration as config
import static
from configuration import MESSAGE_SEPARATOR as SEP
from entities.principal import Principal
from static import slash_contain as slash
# #######################    DATA MODEL    ####################### #
from utils import messaging, cryptography, logger


class Merchant(Principal):
    def __init__(self, identifier):
        super().__init__(identifier)


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
