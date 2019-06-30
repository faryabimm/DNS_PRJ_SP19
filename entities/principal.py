import configuration as config
import static
from configuration import MESSAGE_SEPARATOR as SEP
from utils import cryptography, messaging, logger


class Principal:
    def __init__(self, identifier):
        self.identifier = identifier
        self.private_key, self.public_key = cryptography.generate_rsa_private_public_key_pair()
        self.public_keychain = {}
        self.transaction_context = {}
        self.account = (None, None)
        self.transactor_dsa_public_key = None

    # TODO dump and load keychain methods in utils.cryptography

    def update_transaction_context(self, transaction_id, product_request_data, product_id, bid, price, peer_id):
        if transaction_id not in self.transaction_context:
            logger.log_info('added context for transaction `{}`'.format(transaction_id))
        else:
            logger.log_info('updated context for transaction `{}`'.format(transaction_id))

        self.transaction_context[transaction_id] = {
            'transaction_id': transaction_id,
            'product_request_data': product_request_data,
            'product_id': product_id,
            'bid': bid,
            'price': price,
            'peer_id': peer_id
        }

    def get_server_contact_info(self, server_id):
        if server_id not in self.public_keychain:
            contact_info = messaging.transmit_message_and_get_response(config.ADDRESS_BOOK[server_id],
                                                                       static.GET_CONTACT_INFO)
            if server_id == config.TRANSACTOR_ID:
                server_id, server_public_key, server_dsa_public_key = contact_info.split(SEP)
                self.transactor_dsa_public_key = server_dsa_public_key
            else:
                server_id, server_public_key = contact_info.split(SEP)

            self.public_keychain[server_id] = server_public_key

        return server_id, self.public_keychain[server_id]

    def get_transactor_contact(self):
        return self.get_server_contact_info(config.TRANSACTOR_ID)
