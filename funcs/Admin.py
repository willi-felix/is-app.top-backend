from .Database import Database
from .Token import Token

class Admin:
    def __init__(self,auth:Token, db:Database) -> bool:
        self.token = auth
        if not self.token.password_correct(db): return False
        if(db.get_data(self.token).get("permissions",{}).get("admin")): return False
        self.db = db
        return True
    def add_permission(self, perm:str, target=None):
        """
            target: username of reciever
            perm: Permission to give
        """
        if target is None: target = self.token.username
