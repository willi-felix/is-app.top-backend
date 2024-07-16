from pymongo import MongoClient
from pymongo.database import Database as _Database
from pymongo.collection import Collection
from pymongo.cursor import Cursor
from .Token import Token
from .Email import Email
from hashlib import sha256
from cryptography.fernet import Fernet
from .Utils import generate_random_string
import bcrypt
import time
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from Domain import Domain
    
class Database:
    def __init__(self,url:str,encryption_key:str):
        self.cluster: MongoClient = MongoClient(url)
        self.db: _Database = self.cluster["database"]
        self.collection: Collection = self.db["frii.site"]
        self.vuln_collection: Collection = self.db["vulnerabilities"]
        self.verif_codes:dict={}
        self.encryption_key=encryption_key
        self.fernet = Fernet(bytes(encryption_key,"utf-8"))
        self.data_cache:dict={}
        
    def check_database_for_domain(self,domain:str) -> bool:
        cursor:Cursor
        results_found:int=0
        cursor = self.collection.find({f"domains.{domain}":{"$exists":True}})
        for _ in cursor:
            results_found+=1
        return results_found!=0
    
    def __save_data(self,data: dict) -> None:
        """
        Saves data to mongodb
        """
        assert(type(data)==dict)
        self.collection.insert_one(data)
        
    def update_data(self,username: str, key: str, value: any) -> None:
        self.collection.update_one(
            {"_id": username},
            {"$set":{key:value},},
            upsert=False
        )
        
    def user_logged_in(self,user:Token):
        self.update_data(username=user.username,key="last-login",value=time.time())

    def __delete_user_from_db(self,user:Token) -> bool:
        if(not user.password_correct(self)): return False
        self.remove_from_cache(user)
        self.collection.delete_one({"_id":user.username})
        return True

    def add_domain(self,user: Token, domain_name:str, domain:dict) -> bool:
        if(not user.password_correct(self)): return False
        self.remove_from_cache(user)
        self.collection.update_one({"_id":user.username},{"$set":{f"domains.{domain_name}":domain}})
        return True
    
    def modify_domain(self,user:Token,domain: str, domain_data:dict) -> bool:
        if(not user.password_correct(self)): return False
        assert(domain!=None)
        self.remove_from_cache(user)
        self.collection.update_one({"_id":user.username},{"$set":{f"domains.{domain}":domain_data}})
    
    def get_data(self,user:Token) -> dict:
        if(self.__get_cache(user)!=None): 
            return self.__get_cache(user)
        cursor: Cursor
        results_found: list = []
        cursor = self.collection.find({"_id":user.username})
        for result in cursor:
            results_found.append(result)
        self.__add_to_cache(results_found[0],user)
        if(results_found.__len__()!=0):
            return results_found[0]
        else:
            raise IndexError("No matches for username.")
    def __user_exists(self,user: str) -> bool:
        cursor:Cursor
        results:int=0
        cursor = self.collection.find({"_id":user})
        for _ in cursor:
            results+=1
        return results!=0
        
    def create_user(self,username: str, password: str, email: str, language: str, country: str, time_signed_up) -> bool:
        original_username=username
        username = str(sha256(username.encode("utf-8")).hexdigest())
        password: str = str(sha256(password.encode("utf-8")).hexdigest())
        
        if self.__user_exists(username): 
            return False
        data: dict = {}
        data["_id"] = username
        data['email'] = (self.fernet.encrypt(bytes(email,'utf-8')).decode(encoding='utf-8')) # the encrypted email, but it is less encrypted
        data['password'] = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(encoding='utf-8') # the encrypted password
        data["display-name"] = (self.fernet.encrypt(bytes(username,'utf-8')).decode(encoding='utf-8')) # their display name, I don't think this can be changed tho lol
        data['lang'] = language 
        data['country'] = country
        data["created"] = time_signed_up
        data["last-login"] = time.time() 
        data["permissions"] = {} 
        data["verified"] = False 
        data["domains"] = {}
        self.__save_data(data) 
        self.send_verify_email(email,username,original_username)
        return True
    
    def get_gpdr(self,token:Token):
        if(not token.password_correct(self)): return {"Error":"Invalid credentials","code":"1001"}
        a = self.get_data(token)
        return {"user_id":a["_id"],"location":a["country"],"creation_date":a["created"],"domains":a["domains"],"lang":a["lang"],"last_login":a["last-login"],"permissions":a["permissions"],"verified":a["verified"]}
    
    def get_basic_user_data(self,token:Token) -> dict:
        """Gets the basic userdate

        Args:
            token (Token): user auth token

        Returns:
            error:
                `{"Error":True, "code":...,"message":...}` 
            success:
                `{"username":str,"email":str,"lang":str,"country":str,"created":float,"verified":bool}`
            codes:
                1001 - Invalid credentials
        """
        if(not token.password_correct(self)): return {"Error":True,"code":1001,"message":"Invalid credentials"}
        data = self.get_data(token)
        return {
            "username": (self.fernet.decrypt(str.encode(data["display-name"]))).decode("utf-8"),
            "email": (self.fernet.decrypt(str.encode(data["email"]))).decode("utf-8"),
            "lang": data["lang"],
            "country": data["country"],
            "created": data["created"],
            "verified": data["verified"]
        }   
        
    def is_verified(self,token:Token) -> bool:
        data = self.get_basic_user_data(token)
        return (data.get("verified",False))
    
    def get_permission(self, token:Token,permission:str,default:any)->any:
        return self.get_data(token).get("permissions",{}).get(permission,default)
    
    def remove_from_cache(self,token:Token) -> None:
        del self.data_cache[token.string_token]
    
    def __add_to_cache(self,data:list,token:Token) -> list:
        """Adds cache item

        Args:
            data (dict): `get_data()` of user
            token (Token): user token

        Returns:
            list: given data
        """
        self.data_cache[token.string_token] = {
            "expire": time.time()+30,
            "data": data
        }
        return data
    
    def __get_cache(self,token:Token) -> list:
        """Gets data from cache

        Args:
            token (Token): User auth token

        Returns:
            list: Cached user data
        """
        if(token.string_token not in self.data_cache): return None
        if(self.data_cache.get(token.string_token,{}).get("expire",0) < time.time()): self.remove_from_cache(token); return None
        return self.data_cache.get(token.string_token,{}).get("data")
    
    def delete_account(self,token:Token, domain:'Domain') -> dict:
        """Deletes account and domains associated WARNING: INNER FUNCTION. Call with `email.delete_user()`

        Args:
            token (Token): Auth token
            domain (Domain): Instance of Domain for deleting domains

        Returns:
            errors:
                `{"Error":True,"Errors":{domain:code, user:code}}` 
            success:
                `{"Error":False}` 
        """
        if(not token.password_correct()): return {"Error":True,"code":1001}
        failed:dict={}
        user_domains:dict=self.get_data(token)["domains"]
        for key, _ in  user_domains.items():
            status=domain.delete_domain(token,key)
            if(status!=1):
                failed[key]=status

        deletion_status= self.__delete_user_from_db(token)
        if(deletion_status!=1):
            failed["user"]=deletion_status
            
        response:dict={"Error":False}
        if(failed.__len__()!=0):
            response["Error"]=True,
            response["Errors"]=failed
        return response
            
        