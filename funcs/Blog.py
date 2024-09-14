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
        if not self.db.get_data(token)["permissions"].get("blog",False): raise PermissionError("User does nto have permissions to do this")
        if(url is None):
            url=title.lower().replace(" ","")
        self.db.blog_collection.insert_one({
            "_id":url[:24],
            "date": round(time.time()),
            "title":title,
            "body":body
        })

    def get_list(self,articles:int) -> list:
        """Gets the n articles and returns them as {url:string, created:unix_timestamp(int)}
        NOTE:`articles` < 50
        """
        if(articles>50):
            l.warn(f"Tried to get more than 50 articles {articles}. Denying request")
            raise ValueError("Maximum allowed articles is 50")
        results = []
        cursor = self.db.blog_collection.find().sort({"date":-1}).limit(articles)
        for article in cursor:
            results.append({"url":article["_id"], "created": article["date"]})
        return results
