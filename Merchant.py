import Customer
import Transaction
import Principal
import utils.cryptography as crypto

class Merchant:
    def __init__(self, id, PK):
        self.id = id
        self.PK = PK
        self.PUK = dict()

    def get_PUK(self, merchant_id):
        ## TODO: get PUK from file or something!
        pass

    def parse_auth2m(self, message):
        ## TODO: recive message from C
        customer_id = ""
        c2m = crypto.decrypt_asym(message, self.PUK[customer_id])
        c2m = crypto.decrypt_sym(c2m, self.PK[1])
        c2m =

    # def add_connection(self, merchant, hidden):
    #     if hidden:
    #         self.pseudonym = ''.join(random.sample(letters, 8))
    #     self.m_dict[merchant] = self.pseudonym
    #     return id, merchant, self.pseudonym

    def send_auth2c(self, merchant_id):
        def gen_auth2c(self, merchant_id):
            K = crypto.generate_symmetric_key()
            c2m = [self.id, merchant_id, dt.now().timestamp(), K]
            c2m = crypto.encrypt_asym('$'.join(c2m), self.PUK[merchant_id])
            c2m = crypto.encrypt_asym(c2m, self.PK[1])
        c2m = gen_auth2m(merchant_id)
        ##TODO: send message!
