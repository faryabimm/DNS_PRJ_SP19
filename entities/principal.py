import configuration as config
import static
from configuration import MESSAGE_SEPARATOR as SEP
from utils import cryptography, messaging


class Principal:
    def __init__(self, identifier):
        self.identifier = identifier
        self.private_key, self.public_key = cryptography.generate_private_public_key_pair()
        self.public_keychain = {}
        self.transactor_id = None

    # TODO dump and load keychain methods in utils.cryptography

    def get_server_contact_info(self, server_id):
        if server_id not in self.public_keychain:
            contact_info = messaging.transmit_message_and_get_response(config.ADDRESS_BOOK[server_id], static.GET_CONTACT_INFO)
            server_id, server_public_key = contact_info.split(SEP)

            self.public_keychain[server_id] = server_public_key

        return server_id, self.public_keychain[server_id]

    def get_transactor_contact(self):
        return self.get_server_contact_info(config.TRANSACTOR_ID)
