from enum import Enum


class TransactionResultType(Enum):
    SUCCESS = b'success'
    FAILURE = b'failure'
