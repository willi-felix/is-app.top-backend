from .Logger import Logger
from .Token import Token
from .Database import Database
from .Utils import CredentialError
import time
l = Logger("blog.py","","")

class Blog:
    def __init__(self,db:Database):
        self.db = db
    def get(self,code:str) -> dict:
        l.trace(f"GETting blog {code}")

        data = self.db.blog_collection.find_one({"_id":code})
        if(type(data) is dict):
            return data
        else:
            l.info(f"Blog {code} was not found in database")
            raise KeyError(f"Blog {code} not foun in database!")
    def create(self,token:Token, title:str,body:str,url=None) -> dict:
        if not token.password_correct(self.db): raise CredentialError("Password not correct",None)
        if not self.db.get_data(token)["permissions"]["blog"]: raise PermissionError("User does nto have permissions to do this")
        if(url is None):
            url=title.replace(" ","")
        self.db.blog_collection.insert_one({
            "_id":url[:24],
            "date": round(time.time()),
            "title":title,
            "body":body
        })
