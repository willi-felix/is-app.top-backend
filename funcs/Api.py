from __future__ import annotations
from enum import Enum
from typing import TYPE_CHECKING
# pylint: disable=relative-beyond-top-level
from .Utils import generate_random_string
if TYPE_CHECKING:
    from Database import Database
    from Token import Token

class Permission(Enum):
    M_TYPE=0
    M_DOMAIN:1
    M_CONTENT:2
    DELETE:3
    DETAILS:4

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
        user_domains = database.get_data(token).get("domains",{})
        for domain in domains:
            if(domain not in list(user_domains.keys())):
                raise PermissionError("User does not own domain")

        database.api_collection.insert_one({
            "_id":api_key,
            "perms":permissions_,
            "domains":domains,
            "comment":comment  })
        return api_key
    def __init__(self,key:str,database:Database)->None:
        self.key:str=key
        self.db=database
        self.permissions=self.__get_perms()
        self.domains=self.__get_domains()
    
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
    
    def __get_perms(self) -> list:
        cursor = self.db.api_collection.find({"_id":self.key})
        keys_found:list=[]
        for result in cursor:
            keys_found.append(result)
        result:dict = keys_found[0]
        permissions:list = result.get("perms",[])
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
        cursor = self.db.api_collection.find({"_id":self.key})
        keys_found:list=[]
        for result in cursor:
            keys_found.append(result)
        result:dict = keys_found[0]
        return result.get("domains",[])