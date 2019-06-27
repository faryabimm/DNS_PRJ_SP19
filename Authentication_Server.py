import Customer
import Merchant

class AS:
    def __init__(self):
        self.customers = dict()
        self.merchents = dict()
        self.TGS_CM = TGS()
        self.TGS_NM = TGS()
        self.PGS = PGS()

    def add_principal(self, principal_id, principal_password):
        principal_key = hash(principal_password)
        self.customers[principal_id] = principal_key
        return principal_key



    # def get_key(self, customer_id):
    #     return self.customers[customer_id]


class TGS:
    def __init__(self, principals, servers):




#
# class TGS_NM:
#     def __init__(self):

class PGS:
    def __init__(self):



