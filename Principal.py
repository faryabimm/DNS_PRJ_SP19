
class Principal:
    def __init__(self, id, password, AS):
        self.id = id
        self.password = password
        self.AS = AS
        self.AS_key = self.AS.add_c(self.id, self.password)
        self.PKs = self.AS.get




