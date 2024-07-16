from __future__ import annotations
from pymongo.cursor import Cursor
from hashlib import sha256
import bcrypt 
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from Database import Database

class Token:
    
    def __split_token(self,token:str) -> tuple:
        assert("|" in token)
        split_token = token.split("|")
        split_token.reverse()
        return split_token
    
    def __init__(self,token:str):
        token_data:tuple = self.__split_token(token)
        self.string_token:str=token
        self.username:str=token_data[0]
        self.password:str=token_data[1]

    
    def __is_valid(self,db:Database) -> bool:
        cursor: Cursor
        results_found: int=0
        cursor = db.collection.find({"_id":self.username})
        for _ in cursor:
            results_found+=1
        return results_found==1
    
    def password_correct(self,db: Database) -> bool:
        if(not self.__is_valid(db)): return False
        try:
            data = db.get_data(self)
        except IndexError:
            return False
        return bcrypt.checkpw(self.password.encode("utf-8"), data["password"].encode("utf-8"))
    
    def generate(username:str, password:str) -> str:
        return f"{sha256(password.encode('utf-8'))}|{sha256(username.encode('utf-8'))}"

