import random
import string

import Principal
import Merchant
import Transaction

letters = string.ascii_lowercase

class Customer(Principal):
    def __init__(self, id, password, AS):
        self.m_dict = dict()
        self.pseudonym = self.id

    # def add_connection(self, merchant, hidden):
    #     if hidden:
    #         self.pseudonym = ''.join(random.sample(letters, 8))
    #     self.m_dict[merchant] = self.pseudonym
    #     return id, merchant, self.pseudonym



