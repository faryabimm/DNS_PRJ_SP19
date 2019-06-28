import random
import string

import Principal
import Merchant
import Transaction
import utils.cryptography as crypto
from datetime import datetime as dt

from Netbill import letters


class Customer:
    def __init__(self, id, password, PK, pgs_puk):
        self.id = id
        self.password = password
        self.PK = PK
        self.PUK = dict()
        self.merchants = dict()
        self.pgs_puk = pgs_puk




    # def add_connection(self, merchant, hidden):
    #     if hidden:
    #         self.pseudonym = ''.join(random.sample(letters, 8))
    #     self.m_dict[merchant] = self.pseudonym
    #     return id, merchant, self.pseudonym

    def get_ticket(self, merchant_id, hidden=True):
        if hidden:
            def get_PUK():
                ## TODO: get PUK from file or something!
                pass

            K = crypto.generate_symmetric_key()
            def send_auth2m():
                def gen_auth2m(self, merchant_id):
                    c2m = [self.id, merchant_id, dt.now().timestamp(), K]
                    c2m = crypto.encrypt_asym_with_signature(b'$'.join(c2m), self.PK[0], self.PUK[merchant_id])
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
        else:
            K1 = crypto.generate_symmetric_key()
            K2 = b""
            def c2p():
                ts = dt.now().timestamp()
                message = [self.id, merchant_id, ts, K1]
                message = b"$".join(message)
                message = crypto.encrypt_asym_with_signature(
                    message, self.PK[0], self.pgs_puk)
                ##TODO: send message

            def p2c():
                ##TODO: receive message
                message = b"" ##TODO
                message = crypto.decrypt_sym(message, K1)
                message = message.split(b"$")
                K2 = message[0]
                ps = message[1] ##TODO: send this!
                ##TODO: send message to the merchant

            def m2c():
                ##TODO: recieve
                message = b"" ##TODO
                message = crypto.decrypt_sym(message, K2)
                message = message.split(b"$")
                T_CM = message[0]
                CM = message[1]
                self.merchants[merchant_id] = (T_CM, CM)


            ##TODO
            pass







