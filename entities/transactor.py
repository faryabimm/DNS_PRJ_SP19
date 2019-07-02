from flask import Flask, request

import configuration as config
import static
from configuration import MESSAGE_SEPARATOR as SEP
from entities.psudonym_types import PsudonymTypes
from entities.transaction_result_types import TransactionResultType
from static import slash_contain as slash
from utils import cryptography, generator
from utils import logger
from utils import messaging


# #######################    DATA MODEL    ####################### #

class Transactor:
    """
    NetBill entity
    """

    def __init__(self):
        self.identifier = config.TRANSACTOR_ID
        self.private_key, self.public_key = cryptography.generate_rsa_private_public_key_pair()
        self.dsa_private_key, self.dsa_public_key = cryptography.generate_dsa_private_public_key_pair()
        self.public_keychain = {}
        self.credit_accounts = {}
        self.past_epoids = set()


# ####################### ENTITY ELEMENTS  ####################### #
app = Flask(__name__)
data = Transactor()


# #######################  SERVER UTILITY  ####################### #

def run_server(address):
    host, port = address.split(':')
    app.run(host=host, port=port)


# ####################### SERVICE METHODS  ####################### #


def get_account_balance_bytes(identifier):
    if identifier not in data.credit_accounts:
        logger.log_warn('identifier `{}` not found.'.format(identifier))
        return

    balance = data.credit_accounts[identifier][1]

    if balance == int(balance):
        return bytes(str(int(balance)), encoding='utf-8') + config.CURRENCY
    else:
        return bytes(str(balance), encoding='utf-8') + config.CURRENCY


def get_account_number(identifier):
    if identifier not in data.credit_accounts:
        logger.log_warn('identifier `{}` not found.'.format(identifier))
        return

    return data.credit_accounts[identifier][0]


def get_account_balance(identifier):
    if identifier not in data.credit_accounts:
        logger.log_warn('identifier `{}` not found.'.format(identifier))
        return

    return data.credit_accounts[identifier][1]


def apply_credit_delta(identifier, delta):
    if identifier not in data.credit_accounts:
        logger.log_warn('identifier `{}` not found.'.format(identifier))
        return

    data.credit_accounts[identifier] = (
        data.credit_accounts[identifier][0], data.credit_accounts[identifier][1] + delta)


@app.route(slash(static.GET_CONTACT_INFO), methods=['POST'])
def get_contact_info():
    logger.log_access(request)
    contact_info = SEP.join([data.identifier, data.public_key, data.dsa_public_key])
    return contact_info, 200


@app.route(slash(static.CREATE_PSUDONYM), methods=['POST'])
def create_psudonym():
    logger.log_access(request)
    message = messaging.get_request_data(request)
    two_layer_enc_message, encrypted_key, nonce, timestamp, signature = message.split(SEP)
    plain_message = cryptography.two_layer_sym_asym_decrypt(SEP.join([two_layer_enc_message, encrypted_key]),
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

    if warn_message is not None:
        logger.log_warn(warn_message)
        return warn_message, 403

    psudonym_symmetric_key = cryptography.generate_symmetric_key()

    psudonym = generator.generate_random_identity()
    timestamp = generator.get_timestamp()

    psudonym_ticket = SEP.join([psudonym, merchant_identifier, timestamp, psudonym_symmetric_key])
    psudonym_ticket_two_layer_enc = \
        cryptography.two_layer_sym_asym_encrypt(psudonym_ticket, data.public_keychain[merchant_identifier])
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
    message = cryptography.two_layer_sym_asym_decrypt(message_enc, data.private_key)

    client_identifier, client_public_key, transactor_identifier = message.split(SEP)

    warn_message = None
    if transactor_identifier != data.identifier:
        warn_message = 'invalid transactor identifier.'
    elif client_identifier in data.public_keychain:
        warn_message = 'client exists. updating.'

    if warn_message is not None:
        logger.log_warn(warn_message)
        return warn_message, 403

    data.public_keychain[client_identifier] = client_public_key

    account_number = generator.generate_random_account_number()
    nonce = generator.generate_nonce()

    account_receipt = SEP.join([account_number, nonce])
    account_receipt_enc = cryptography.two_layer_sym_asym_encrypt(account_receipt, client_public_key)
    data.credit_accounts[client_identifier] = ((account_number, nonce), config.INITIAL_CLIENT_CREDIT)

    return account_receipt_enc, 200


@app.route(slash(static.REGISTER_MERCHANT), methods=['POST'])
def register_merchant():
    logger.log_access(request)
    message_enc = messaging.get_request_data(request)
    message = cryptography.two_layer_sym_asym_decrypt(message_enc, data.private_key)

    merchant_identifier, merchant_public_key, transactor_identifier = message.split(SEP)

    warn_message = None
    if transactor_identifier != data.identifier:
        warn_message = 'invalid transactor identifier.'
    elif merchant_identifier in data.public_keychain:
        warn_message = 'merchant exists. aborting.'

    if warn_message is not None:
        logger.log_warn(warn_message)
        return warn_message, 403

    data.public_keychain[merchant_identifier] = merchant_public_key

    account_number = generator.generate_random_account_number()
    nonce = generator.generate_nonce()

    account_receipt = SEP.join([account_number, nonce])
    account_receipt_enc = cryptography.two_layer_sym_asym_encrypt(account_receipt, merchant_public_key)
    data.credit_accounts[merchant_identifier] = ((account_number, nonce), config.INITIAL_MERCHANT_CREDIT)

    return account_receipt_enc, 200


@app.route(slash(static.REGISTER_GROUP), methods=['POST'])
def register_group():
    logger.log_access(request)
    message_enc = messaging.get_request_data(request)
    message = cryptography.two_layer_sym_asym_decrypt(message_enc, data.private_key)

    group_identifier, group_public_key, transactor_identifier = message.split(SEP)

    warn_message = None
    if transactor_identifier != data.identifier:
        warn_message = 'invalid transactor identifier.'
    elif group_identifier in data.public_keychain:
        warn_message = 'group exists. aborting.'

    if warn_message is not None:
        logger.log_warn(warn_message)
        return warn_message, 403

    data.public_keychain[group_identifier] = group_public_key

    return 'success', 200


@app.route(slash(static.CREATE_TICKET), methods=['POST'])
def create_ticket():
    logger.log_access(request)
    message = messaging.get_request_data(request)
    encrypted_data = cryptography.strip_clear_signed_message(message)
    decrypted_data = cryptography.two_layer_sym_asym_decrypt(encrypted_data, data.private_key)

    client_identity, transactor_id, timestamp, symmetric_key = decrypted_data.split(SEP)

    if data.identifier != transactor_id:
        warn_message = 'transactor id does not match.'
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


@app.route(slash(static.SUBMIT_ENDORSED_SIGNED_EPO), methods=['POST'])
def submit_signed_endorsed_epo():
    logger.log_access(request)
    message = messaging.get_request_data(request)
    ticket, signed_endorsed_epo_enc = message.split(SEP)
    merchant_sym_key, merchant_identity, _, _, _ = cryptography.open_ticket(ticket, data.private_key)

    signed_endorsed_epo_clear_signed = cryptography.decrypt_sym(signed_endorsed_epo_enc, merchant_sym_key)

    signed_endorsed_epo, verified = cryptography.verify_clear_signature(signed_endorsed_epo_clear_signed,
                                                                        data.public_keychain[merchant_identity])

    if not verified:
        warn_message = 'client epo signature not verified'
        logger.log_warn(warn_message)
        return warn_message, 403

    parts = signed_endorsed_epo.split(SEP)
    product_key = parts[-1]
    merchant_memo = parts[-2]
    merchant_account = parts[-3]
    signed_epo = SEP.join(parts[:-3])

    epo = cryptography.strip_clear_signed_message(signed_epo)

    parts = epo.split(SEP)

    client_identity = parts[0]
    product_id = parts[1]
    price_to_pay = parts[2]
    epo_merchant_id = parts[3]
    enc_product_checksum = parts[4]
    product_request_data_checksum = parts[5]
    account_data_checksum = parts[6]
    epoid_plain = SEP.join(parts[7:10])
    client_transactor_ticket = parts[10]
    order_for_transactor = parts[11]

    if client_identity not in data.public_keychain:
        warn_message = 'unknown client `{}`'.format(client_identity)
        logger.log_warn(warn_message)
        return warn_message, 403

    _, verified = cryptography.verify_clear_signature(signed_epo, data.public_keychain[client_identity])

    client_sym_key, ticket_client_identity, _, _, _ = cryptography.open_ticket(client_transactor_ticket,
                                                                               data.private_key)

    price_number = generator.get_price_number(price_to_pay)

    order_for_transactor_plain = cryptography.decrypt_sym(order_for_transactor, client_sym_key)

    client_authorization, client_account_number, client_account_nonce, client_memo = order_for_transactor_plain.split(
        SEP)

    warn_message = None
    if not verified:
        warn_message = 'client epo signature not verified'
    elif epo_merchant_id != merchant_identity:
        warn_message = '`merchant_id` mismatch'
    elif client_identity != ticket_client_identity:
        warn_message = '`client_id` mismatch'
    elif (client_account_number, client_account_nonce) != data.credit_accounts[client_identity][0]:
        warn_message = 'mismatch client account data'
    elif merchant_account != data.credit_accounts[merchant_identity][0][0]:
        warn_message = 'mismatch client account number'
    elif cryptography.cryptographic_checksum(
            SEP.join(data.credit_accounts[client_identity][0])) != account_data_checksum:
        warn_message = 'corrupt client account checksum data'
    elif epoid_plain in data.past_epoids:
        warn_message = 'repetitive epo'
    elif data.credit_accounts[client_identity][1] < price_number:
        warn_message = 'insufficient funds'

    if warn_message is not None:
        logger.log_warn(warn_message)
        return warn_message, 403

    data.past_epoids.add(epoid_plain)

    apply_credit_delta(client_identity, -price_number)
    apply_credit_delta(merchant_identity, +price_number)

    result = TransactionResultType.SUCCESS.value

    transaction_receipt_plain = SEP.join([
        result,
        client_identity,
        price_to_pay,
        product_id,
        merchant_identity,
        product_key,
        epoid_plain
    ])

    transaction_receipt_dsa_signed = cryptography.dsa_sign(transaction_receipt_plain, data.dsa_private_key)

    flags = b''

    client_receipt_plain = SEP.join([
        epoid_plain,
        client_account_number,
        generator.get_price_bytes(data.credit_accounts[client_identity][1]),
        flags
    ])

    client_receipt = cryptography.encrypt_sym(client_receipt_plain, client_sym_key)

    response_plain = SEP.join([transaction_receipt_dsa_signed, client_receipt])
    response = cryptography.encrypt_sym(response_plain, merchant_sym_key)

    return response, 200


if __name__ == '__main__':
    try:
        run_server(config.ADDRESS_BOOK[config.TRANSACTOR_ID])
    except KeyboardInterrupt:
        logger.log_info('keyboard interrupt, exiting...')
        exit(0)
