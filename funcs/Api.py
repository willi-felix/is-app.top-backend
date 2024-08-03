from __future__ import annotations
from enum import Enum
from typing import TYPE_CHECKING
from hashlib import sha256
# pylint: disable=relative-beyond-top-level
from .Utils import generate_random_string
if TYPE_CHECKING:
    from Database import Database
    from Token import Token

class Permission(Enum):
    M_TYPE=0
    M_DOMAIN=1
    M_CONTENT=2
    DELETE=3
    DETAILS=4

class Api:
    @staticmethod
    def create(token:'Token', permissions_: list, domains: list, comment: str, database:Database) -> str:
        """Creates an API Key

        Args:
            permissions_ (list): list of permissions [view content type domain delete]
            domains (list): list of domains that this will affect
            comment (str): Users left comment
            database (Database): instance of database
        Raises: 
        Returns:
            str: API Key
        """
        api_key:str="$APIV1="+generate_random_string(32)
        print("Normal key: " + api_key)
        user_domains = database.get_data(token).get("domains",{})
        for domain in domains:
            if(domain not in list(user_domains.keys())):
                raise PermissionError("User does not own domain")

        key = {
            "perms":permissions_,
            "domains":domains,
            "comment":comment
        }
        
        encrypted_api_key:str = sha256((api_key+"frii.site").encode("utf-8")).hexdigest()
        database.collection.update_one({"_id":token.username},{"$set":{f"api-keys.{encrypted_api_key}":key}})
        return api_key
    def __init__(self,key:str,database:Database)->None:
        self.key:str=key
        self.perms_class = Permission
        print("Normal key: " + self.key)
        self.db=database
        self.__search_key = sha256((self.key+"frii.site").encode("utf-8")).hexdigest() # frii.site used for salting
        self.valid=True
        try:
            self.permissions=self.__get_perms()
        except IndexError:
            self.valid = False
        self.username=self.__get_username()
        self.domains=self.__get_domains()
        
    def get_domain_id(self,target:str) -> str:
        return self.db.collection.find_one({f"api-keys.{self.__search_key}":{"$exists":True}}).get("domains",{}).get(target,{}).get("id")
    
    def has_permission(self,target:Permission,domain:str, domains:list) -> bool:
        """Checks if API key has permissions to do a certain task

        Args:
            target (Permission): Permission required
            domain (str): Domain that is trying to be modified

        Returns:
            bool: if has
        """
        if domain not in domains: return False
        return target in self.permissions
    
    def required_permissions(self,domain:str,type_:str,content:str) -> list[Permission]:
        """Gives a list of required permissions

        Args:
            domain (str): domain affected
            type_ (str): domain type
            content (str): domain content

        Returns:
            list[Permission]: list of permissions
        """
        needed_perms:list[Permission] = []
        target_domain = self.db.collection.find_one({f"api-keys.{self.__search_key}":{"$exists":True}}).get("domains",{}).get(domain,{})
        print("Target domain: "+str(target_domain))
        if(target_domain.get("type")!=type_):
            needed_perms.append(Permission.M_TYPE)
        if(target_domain.get("ip")!=content):
            needed_perms.append(Permission.M_CONTENT)
        print("Needed perms: "+ str(needed_perms))
        return needed_perms
    
    def __get_perms(self) -> list:
        result = self.db.collection.find_one({f"api-keys.{self.__search_key}":{"$exists":True}})
        print("Key from db: " +str(result))
        permissions:list = result.get("api-keys",{}).get(self.__search_key,{}).get("perms")
        print("Permissions from db: "+str(permissions))
        permissions_list:list = []
        for permission in permissions:
            # pylint: disable=multiple-statements
            if(permission=="view"):  permissions_list.append(Permission.DETAILS)
            if(permission=="content"):  permissions_list.append(Permission.M_CONTENT)
            if(permission=="domain"):  permissions_list.append(Permission.M_DOMAIN)
            if(permission=="type"):  permissions_list.append(Permission.M_TYPE)
            if(permission=="delete"):  permissions_list.append(Permission.DELETE)
        return permissions_list
    
    def __get_domains(self) -> list:
        result = self.db.collection.find_one({f"api-keys.{self.__search_key}":{"$exists":True}})
        return result.get("domains",[])
    
    def __get_username(self) -> str:
        return self.db.collection.find_one({f"api-keys.{self.__search_key}":{"$exists":True}}).get("_id")