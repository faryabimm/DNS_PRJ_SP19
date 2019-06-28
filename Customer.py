import random
import string

import Principal
import Merchant
import Transaction
import utils.cryptography as crypto
from datetime import datetime as dt

letters = string.ascii_lowercase

class Customer:
    def __init__(self, id, password, PK):
        self.id = id
        self.password = password
        self.PK = PK
        self.PUK = dict()
        self.merchants = dict()




    # def add_connection(self, merchant, hidden):
    #     if hidden:
    #         self.pseudonym = ''.join(random.sample(letters, 8))
    #     self.m_dict[merchant] = self.pseudonym
    #     return id, merchant, self.pseudonym

    def get_ticket(self, merchant_id):

        def get_PUK(self, merchant_id):
            ## TODO: get PUK from file or something!
            pass

        K = crypto.generate_symmetric_key()
        def send_auth2m():
            def gen_auth2m(self, merchant_id):
                c2m = [self.id, merchant_id, dt.now().timestamp(), K]
                c2m = crypto.encrypt_asym(b'$'.join(c2m), self.PK[0], self.PUK[merchant_id])
            c2m = gen_auth2m(merchant_id)
            ##TODO: send message!

        def recive_auth2m():
            ## TODO: receive
            message = "" ##TODO
            message = crypto.decrypt_sym(message, K)
            message = message.split(b"$")
            T_CM = message[0]
            CM = message[1]
            self.merchants[merchant_id] = (T_CM, CM)




