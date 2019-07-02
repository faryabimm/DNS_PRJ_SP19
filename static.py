GET_CONTACT_INFO = 'get_contact_info'
CREATE_PSUDONYM = 'create_psudonym'
CREATE_TICKET = 'create_ticket'
CREATE_CREDENTIALS = 'create_credentials'
REGISTER_CLIENT = 'register_client'
REGISTER_MERCHANT = 'register_merchant'
REGISTER_GROUP = 'register_group'
REQUEST_PRICE = 'request_price'
REQUEST_GOODS = 'request_goods'
SUBMIT_SIGNED_EPO = 'submit_signed_epo'
SUBMIT_ENDORSED_SIGNED_EPO = 'submit_endorsed_signed_epo'


def slash_contain(input_string):
    return '/' + input_string + '/'
