import time
from hashlib import sha256
from typing import TYPE_CHECKING

import bcrypt
from cryptography.fernet import Fernet
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.cursor import Cursor
from pymongo.database import Database as _Database

# pylint: disable=relative-beyond-top-level
from .Email import Email
from .Token import Token
from .Logger import Logger
import os
from dotenv import load_dotenv
load_dotenv()

l = Logger("Database.py",os.getenv("DC_WEBHOOK"),os.getenv("DC_TRACE"))

if TYPE_CHECKING:
    from Domain import Domain
    from Email import Email

class Database:
    def __init__(self,url:str,encryption_key:str):
        self.cluster: MongoClient = MongoClient(url)
        self.db: _Database = self.cluster["database"]
        self.collection: Collection = self.db["frii.site"]
        self.vuln_collection: Collection = self.db["vulnerabilities"]
        self.translation_collection: Collection = self.db["translations"]
        self.status_collection: Collection = self.db["status"]
        self.blog_collection:Collection = self.db["blog"]
        self.codes: Collection = self.db["codes"]
        self.api_collection:Collection = self.db["api"]
        self.verif_codes:dict={}
        self.encryption_key=encryption_key
        self.fernet = Fernet(bytes(encryption_key,"utf-8"))
        self.data_cache:dict={}
        self.status_data = None

    @l.time
    def check_database_for_domain(self,domain:str) -> bool:
        cursor:Cursor
        results_found:int=0
        cursor = self.collection.find({f"domains.{domain}":{"$exists":True}})
        for _ in cursor:
            results_found+=1
        return results_found!=0

    @l.time
    def __save_data(self,data: dict) -> None:
        """
        Saves data to mongodb
        """
        assert(type(data) is dict)
        self.collection.insert_one(data)


    @l.time
    def update_data(self,username: str, key: str, value: any) -> None:
        self.collection.update_one(
            {"_id": username},
            {"$set":{key:value},},
            upsert=False
        )

    def user_logged_in(self,user:Token):
        self.update_data(username=user.username,key="last-login",value=time.time())

    @l.time
    def __delete_user_from_db(self,user:Token) -> bool:
        if(not user.password_correct(self)): return False
        self.remove_from_cache(user)
        self.collection.delete_one({"_id":user.username})
        return True

    @l.time
    def add_domain(self,user: Token, domain_name:str, domain:dict) -> bool:
        l.info(f"Adding domain {domain_name} to user")
        if(not user.password_correct(self)): return False
        self.remove_from_cache(user)
        self.collection.update_one({"_id":user.username},{"$set":{f"domains.{domain_name}":domain}})
        return True

    @l.time
    def modify_domain(self,user:Token,domain: str, domain_data:dict) -> bool:
        domain = domain.replace(".","[dot]")
        l.info(f"Modifying domain {domain}")
        if(not user.password_correct(self)): return False
        assert(domain!=None)
        self.modify_cache_domain(user,domain,domain_data)
        self.collection.update_one({"_id":user.username},{"$set":{f"domains.{domain}":domain_data}})

    @l.time
    def get_data(self,user:Token) -> dict:
        if(self.__get_cache(user) is not None):
            l.trace(f"Found user {user.username} in cache")
            return self.__get_cache(user)
        cursor: Cursor
        results_found: list = []
        cursor = self.collection.find({"_id":user.username})
        for result in cursor:
            results_found.append(result)
        self.__add_to_cache(results_found[0],user)
        self.user_logged_in(user)
        if(results_found.__len__()!=0):
            return results_found[0]
        else:
            l.warn(f"`get_data` no matches for username {user.username}")
            raise IndexError("No matches for username.")
    @l.time
    def __user_exists(self,user: str) -> bool:
        cursor:Cursor
        results:int=0
        cursor = self.collection.find({"_id":user})
        for _ in cursor:
            results+=1
        return results!=0

    @l.time
    def __email_taken(self,email:str) -> bool:
        email_hash = str(sha256((email+"supahcool").encode("utf-8")).hexdigest())
        l.info(f"Checking if email {email_hash} is in use")
        cursor:Cursor
        results:int=0
        cursor = self.collection.find({"email-hash":email_hash})
        for _ in cursor:
            results +=1
        return results != 0

    def admin_get_basic_data(self,token:Token,id:str) -> dict:
        if(not token.password_correct(self)):
            l.permission(f"User {token.username} tried to access `admin_get_basic_data` (invalid password)")
            return {"Error":True,"code":1000}
        if(not self.get_data(token).get("permissions").get("userdetails",False)):
            l.permission(f"User {token.username} tried to access `admin_get_basic_data` (no permissions)")
            return {"Error":True,"code":1001,"message":"Token does not have permissions"}
        raw_data:dict = self.collection.find_one(id)
        return {
            "Error":False,
            "username": (self.fernet.decrypt(str.encode(raw_data["display-name"]))).decode("utf-8"),
            "email": (self.fernet.decrypt(str.encode(raw_data["email"]))).decode("utf-8"),
            "created": raw_data["created"],
            "last-login": raw_data["last-login"],
            "domains": raw_data.get("domain"),
            "permissions": raw_data.get("permissions")
        }

    def admin_get_emails(self,token:Token,condition:dict) -> dict:
        if(not token.password_correct(self)):
            l.permission(f"User {token.username} tried to access `admin_get_basic_data` (invalid password)")
            return {"Error":True,"code":1000}

        if(not self.get_data(token).get("permissions").get("userdetails",False)):
            l.permission(f"User {token.username} tried to access `admin_get_basic_data` (no permissions)")
            return {"Error":True,"code":1001,"message":"Token does not have permissions"}

        results = self.collection.find(condition)
        emails:list=[]
        for result in results:
            emails.append(self.fernet.decrypt(str.encode(result["email"])).decode("utf-8"))
        return {"Error":False,"emails":emails}

    @l.time
    def create_user(self,username: str, password: str, email: str, language: str, country, time_signed_up, emailInstance:'Email') -> dict:
        """Creates a new user

        Args:
            username (str): Username of new user
            password (str): Password of new user
            email (str): email of the new user
            language (str): users language in the brwser
            country (str): users country
            time_signed_up (_type_): current tmie
            emailInstance (Email): instance of Email to send verfication

        Returns:
            error:
                `{"Error":True,"code":...,"message":...}`
            success:
                `{"Error":False}`
            codes:
                1001 - User exists
                1002 - email in use
                1003 - Invalid email
        """
        original_username=username
        username = str(sha256(username.encode("utf-8")).hexdigest())
        password: str = str(sha256(password.encode("utf-8")).hexdigest())
        if self.__user_exists(username):
            l.warn("`create_user` Username is already in use")
            return {"Error":True,"code":1001,"message":"User already exists"}
        if self.__email_taken(email):
            l.warn("`create_user` Email is already in use")
            return {"Error":True,"code":1002,"message":"Email aready in use"}
        data: dict = {}
        data["_id"] = username
        data['email'] = (self.fernet.encrypt(bytes(email,'utf-8')).decode(encoding='utf-8')) # the encrypted email, but it is less encrypted
        data['password'] = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(encoding='utf-8') # the encrypted password
        data["display-name"] = (self.fernet.encrypt(bytes(username,'utf-8')).decode(encoding='utf-8')) # their display name, I don't think this can be changed tho lol
        data['lang'] = language
        data['country'] = country
        data['email-hash'] = str(sha256((email+"supahcool").encode("utf-8")).hexdigest())
        data['accessed-from'] = []
        data["created"] = time_signed_up
        data["last-login"] = time.time()
        data["permissions"] = {"max-domains":3}
        data["verified"] = False
        data["domains"] = {}
        data["feature-flags"] = {}
        data["api-keys"] = {}
        data["credits"] = 15
        self.__save_data(data)
        if(not emailInstance.send_verification(Token(Token.generate(username,password)),email,original_username)):
            l.warn("`create_user` Invalid email")
            return {"Error":True,"code":1003,"message":"Invalid email"}

        return {"Error":False}

    def get_gpdr(self,token:Token):
        if(not token.password_correct(self)):
            l.info("`get_gpdr` Password not correct")
            return {"Error":"Invalid credentials","code":"1001"}
        a = self.get_data(token)
        return {"user_id":a["_id"],"location":a["country"],"creation_date":a["created"],"domains":a["domains"],"lang":a["lang"],"last_login":a["last-login"],"permissions":a["permissions"],"verified":a["verified"]}

    @l.time
    def get_basic_user_data(self,token:Token) -> dict:
        """Gets the basic userdate

        Args:
            token (Token): user auth token

        Returns:
            error:
                `{"Error":True, "code":...,"message":...}`
            success:
                `{"username":str,"email":str,"lang":str,"country":str,"created":float,"verified":bool,"permissions":dict}`
            codes:
                1001 - Invalid credentials
        """
        if(not token.password_correct(self)):
            l.info("`get_basic_user_data` Invalid credentials")
            return {"Error":True,"code":1001,"message":"Invalid credentials"}
        data = self.get_data(token)
        return {
            "username": (self.fernet.decrypt(str.encode(data["display-name"]))).decode("utf-8"),
            "email": (self.fernet.decrypt(str.encode(data["email"]))).decode("utf-8"),
            "lang": data["lang"],
            "country": data["country"],
            "created": data["created"],
            "verified": data["verified"],
            "permissions":data["permissions"]
        }

    @l.time
    def is_verified(self,token:Token) -> bool:
        data = self.get_basic_user_data(token)
        l.info(f"is user {token.username} verified: {data.get('verified',None)}")
        return (data.get("verified",False))

    @l.time
    def get_permission(self, token:Token,permission:str,default:any)->any:
        return self.get_data(token).get("permissions",{}).get(permission,default)

    @l.time
    def remove_from_cache(self,token:Token) -> None:
        try:
            del self.data_cache[token.string_token]
            l.trace(f"Deleted user {token.username} from cache")
        except KeyError:
            l.warn(f"Couldn't delete {token.username} from cache")
            pass

    @l.time
    def __add_to_cache(self,data:list,token:Token) -> list:
        """Adds cache item

        Args:
            data (dict): `get_data()` of user
            token (Token): user token

        Returns:
            list: given data
        """
        l.trace(f"Adding {token.username} to cache")
        self.data_cache[token.string_token] = {
            "expire": time.time()+30,
            "data": data
        }
        return data

    @l.time
    def __get_cache(self,token:Token) -> list:
        """Gets data from cache

        Args:
            token (Token): User auth token

        Returns:
            list: Cached user data
        """
        if(token.string_token not in self.data_cache):
            l.trace(f"User {token.username} not found in cache")
            return None
        if(self.data_cache.get(token.string_token,{}).get("expire",0) < time.time()):
            l.info(f"Cache for user {token.username} has expired")
            self.remove_from_cache(token)
            return None
        return self.data_cache.get(token.string_token,{}).get("data")

    def modify_cache(self,token: Token, key: any, value: any):
        l.trace(f"Modifying cache for user {token.username}")
        if(token.string_token not in self.data_cache):
            l.trace(f"User {token.username} not found in cache")
            self.__add_to_cache()
            return None
        self.data_cache[token.string_token]["data"][key] = value
        return True

    def modify_cache_domain(self, token:Token, key: any, value:dict):
        l.trace(f"Modifying domain {key} from cache")
        if(token.string_token not in self.data_cache):
            l.trace(f"User {token.username} not found in cache")
            return None
        self.data_cache[token.string_token]["data"]["domains"][key] = value
        return True

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
        if(not token.password_correct(self)):
            l.info("`delete_account` password incorrect")
            return {"Error":True,"code":1001}
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
            l.warn(f"Account deletion for user {token.username} failed ({failed})")
            response["Error"]=True,
            response["Errors"]=failed
        return response

    @l.time
    def join_beta(self,token:Token) -> bool:
        if(not token.password_correct(self)): return False
        self.collection.update_one({"_id":token.username},{"$set":{"beta-enroll":True}})
        self.collection.update_one({"_id":token.username},{"$set":{"beta-updated":time.time()}})
        return True

    @l.time
    def leave_beta(self, token:Token) -> bool:
        if(not token.password_correct(self)): return False
        self.collection.update_one({"_id":token.username},{"$set":{"beta-enroll":False}})
        self.collection.update_one({"_id":token.username},{"$set":{"beta-updated":time.time()}})
        return True

    def __get_status_data(self):
        if(self.status_data is None or self.status_data.get("expire",0) < time.time()):
            data = self.status_collection.find_one({"_id":"current"})
            if(data is None): return None
            self.status_data = data
            self.status_data["expire"] = time.time()+60
            return data
        else: return self.status_data

    def get_status(self) -> dict:
        data = self.__get_status_data()
        if(data is None): return {"reports":False}
        else: return {"reports":True, "message":data.get("message","We are experiencing heavy traffic. Features may not work correctly")}
