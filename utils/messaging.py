import requests

from utils import logger


def transmit_message_and_get_response(address, path, message_bytes=None):
    """
    :param path:
    :param address: '<host>:<port>' (str)
    :param message_bytes: message to transmit
    :return:
    """

    response = requests.post('http://' + address + '/' + path, data=message_bytes)

    if not response.ok:
        logger.log_error('post request status is not ok!')

    return response.content


def get_address_from_request(request):
    return request.remote_addr + ':' + request.environ.get('REMOTE_PORT')


def get_request_data(request):
    return request.data
