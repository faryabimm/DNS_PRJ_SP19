import requests

import configuration as config
from utils import messaging

x = messaging.transmit_message_and_get_response(config.TRANSACTOR_ADDRESS, 'a')
y = messaging.transmit_message_and_get_response(config.TRANSACTOR_ADDRESS, 'b')


print(x)
print(y)
