import random
import string
from datetime import datetime as dt

import utils.cryptography as crypto
from Customer import Customer
from Principal import *

letters = string.ascii_lowercase


class Netbill:
    def __init__(self):
        self.merchants = dict()
        self.customers = dict()
        self.PUK = dict()
        self.PGS = self.PGS(self)
        ## TODO: handle PSG
        # self.PGS = PGS()

    def add_customer(self, id, password):
        ##TODO: recive request
        keys = crypto.generate_private_public_key_pair() ##TODO: keys to principal
        new_customer = Customer(id, password, keys, self.PGS.PK[1])
        self.customers[(id, password)] = new_customer
        ##TODO: GIVE PGS PUK to the customer

    def add_merchant(self, id):
        ##TODO recieve request
        keys = crypto.generate_private_public_key_pair()
        new_merchant = Principal(id, keys, self.PGS.PK[1])
        self.merchants[id] = new_merchant
        ##TODO: GIVE PGS PUK to the merchant

    # def updated_PUK(self):
    #     new_PUK = map(lambda key: d[key], d.keys())
    #     list(map(lambda x: x * 2, li))
    #     self.principals
    def begin_transaction(self, customer_id, customer_password, merchant_id, hidden):
        def share_PUK(self, customer, merchant):
            ## TODO: commute public key
            pass

        if not hidden:
            customer = self.customers[(customer_id, customer_password)]
            merchant = self.merchants[merchant_id]
            # customer.get_ticket()
            share_PUK(customer, merchant)

    class PGS:
        def __init__(self, outer):
            self.PK = crypto.generate_private_public_key_pair()
            self.outer = outer

        def pseudonym(self):
            ##TODO: receive message from customer
            msg = ""
            customer_id = b""  ##TODO
            merchant_id = b""  ##TODO
            ts = 0
            K1 = ""
            K2 = crypto.generate_symmetric_key()
            ps = ''.join(random.sample(letters, 8))

            def get_message():
                message = crypto.decrypt_asym_with_signature(msg, self.PK[0], self.outer.PUK[customer_id])
                message = message.split(b"$")
                if customer_id != message[0]:
                    raise Exception("Wrong Source!")
                merchant_id = message[1]
                ts = message[2]
                K1 = message[3]

            def send_message():
                ts = dt.now().timestamp()
                message = list()
                message[0] = K2
                message[1] = crypto.encrypt_asym_with_signature(b"$".join([ps, merchant_id, ts, K1]),
                                                                self.PK[0], self.outer.PUK[merchant_id])
                ### message[2] = crypto.encrypt_asym(b"$".join([ps, merchant_id, ts, K1]), self.PK[0], self.outer.PUK[merchant_id])
                message = b"$".join(message)
                message = crypto.encrypt_sym(message, K1)
                ##TODO: send message

