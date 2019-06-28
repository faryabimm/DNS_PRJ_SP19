import utils.cryptography as crypto
from Principal import *
from Customer import Customer



class Netbill:
    def __init__(self):
        self.merchants = dict()
        self.customers = dict()
        self.PUK = dict()
        # self.PGS = PGS()

    def add_customer(self, id, password):
        ##TODO: recive request
        keys = crypto.generate_private_public_key_pair()
        new_customer = Customer(id, password, keys)
        self.customers[(id, password)] = new_customer

    def add_merchant(self, id):
        ##TODO recieve request
        keys = crypto.generate_private_public_key_pair()
        new_merchant = Principal(id, keys)
        self.merchants[id] = new_merchant

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
            share_PUK(customer, merchant)

#
# class PGS:
#     def __init__(self):
