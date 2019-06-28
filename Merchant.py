import Customer
import Transaction
import Principal
import utils.cryptography as crypto
from datetime import datetime as dt

class Merchant:
    def __init__(self, id, PK):
        self.id = id
        self.PK = PK
        self.PUK = dict()
        self.customers = dict()

    def give_ticket(self, customer_id):
        K = ""
        customer_addr = ""

        def get_PUK(self):
            ## TODO: get PUK from file or something!
            pass

        def send_auth2c():
            def gen_auth2c():
                CM = crypto.generate_symmetric_key()
                ts = dt.now().timestamp()
                lf = 0.1 ##TODO
                T_CM = b''.join([customer_id, customer_addr, self.id, ts, lf])
                self.CM[customer_id] = (T_CM, CM)
                m2c = crypto.encrypt_asym(T_CM, self.PK[1], self.PUK[customer_id])
                ##TODO: send T_CM, CM

        def parse_auth2m():
            ## TODO: recive message from C
            message = "" ##TODO
            customer_addr = "" ## TODO
            customer_id = "" ##TODO
            c2m, valid = crypto.decrypt_asym(message, self.PK[1], self.PUK[customer_id])
            if not valid:
                raise Exception("Authentication Failed!")
            c2m = c2m.split(b"$")
            customer_id = c2m[0]
            merchent_id = c2m[1]
            if not merchent_id == self.id:
                raise Exception("Wrong Destination!")
            timestamp = c2m[2]
            ## TODO: what to do with timestamp?
            K = c2m[3]
            send_auth2c()




    # def add_connection(self, merchant, hidden):
    #     if hidden:
    #         self.pseudonym = ''.join(random.sample(letters, 8))
    #     self.m_dict[merchant] = self.pseudonym
    #     return id, merchant, self.pseudonym


