import utils.cryptography as crypto
from Principal import *



class Netbill:
    def __init__(self):
        self.principals = dict()
        self.PUK = dict()
        self.PGS = PGS()

    def add_principal(self, principal_id, principal_password):
        principal_key = crypto.generate_private_public_key_pair()
        new_principal = Principal(principal_id, principal_password, principal_key)
        self.principals[(principal_id, principal_password)] = new_principal

    # def updated_PUK(self):
    #     new_PUK = map(lambda key: d[key], d.keys())
    #     list(map(lambda x: x * 2, li))
    #     self.principals
    def begin_transaction(self, customer_id, customer_password, merchant_id, hidden):
        def share_PUK(self, A, B):
            ## TODO: commute public key
            pass

        if not hidden:
            share_PUK(self.principals[(customer_id.customer_password)],
                      self.principals[(merchant_id, "")])

            K = crypto.generate_symmetric_key()
            c2m = [customer_id, merchant_id, dt.now().timestamp(), K]
            = crypto.encrypt_asym('$'.join(c2m))


    # def get_key(self, customer_id):
    #     return self.customers[customer_id]


#
# class TGS:
#     def __init__(self, principals, servers):


#
# class TGS_NM:
#     def __init__(self):

class PGS:
    def __init__(self):
