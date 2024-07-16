from __future__ import annotations
import requests
from requests import Response
import time
import string
from typing import TYPE_CHECKING
    
class Domain:
    def __init__(self,db:'Database',email:str,cf_key_w:str, cf_key_r,zone_id):
        self.db:'Database'=db
        self.email = email
        self.cf_key_w = cf_key_w
        self.cf_key_r = cf_key_r
        self.zone_id:str=zone_id
    
    def is_domain_valid(domain: str) -> bool:
        allowed = list(string.ascii_letters)
        allowed.extend(list(string.digits))
        allowed.extend([".","-"])
        valid = all(c in allowed for c in domain) # this *might* work, super hacky tho
        return valid

    def __add_domain_to_user(self,token: 'Token', domain: str, content: str=None,  type: str=None, domain_id: str=None) -> bool:
        data = self.db.get_data(token)
        if(domain not in data["domains"]):  
            domain_data = {
                "ip":content,
                "type":type,
                "registered":time.time(),
                "id":domain_id
            }
            self.db.add_domain(token,domain,domain_data)
            return True
        
        domain_data = data["domains"][domain]
        if(content!=None):
            domain_data["ip"]=content
        if(type!=None):
            domain_data["type"]=type
        self.db.modify_domain(token,domain,domain_data)
        return True
    
    def delete_domain(self,token:'Token', domain: str) -> int:
        """Deletes specified domain
        
        Returns:
            int: -1 not owning domain, 0 passowrd or user not correct, 1 succeed
        """
        if(not token.password_correct(self.db)): return 0
        data = self.db.get_data(token)
        domains: dict = data.get("domains",{})
        if(domain not in domains): return -1
        headers: dict = {
            "Content-Type": "application/json",
            "Authorization": "Bearer "+self.cf_key_w, # cloudflare write token
            "X-Auth-Email": self.email
        }
        response = requests.delete(f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records/{data['domains'][domain]['id']}",headers=headers)
        if(response.status_code==200):
            del domains[domain]
            self.db.update_data(username=token.username,key="domains",value=domains)
        return 1
    
    def get_user_domains(self,database:'Database', token:'Token') -> dict: 
        """Get user domains

        Args:
            database (Database): instance of database
            token (Token): user auth

        Returns:
            error:
                `{"Error":True,"code":...,"message":...}`
            success:
                `{domains:dict}`
            codes:
                1001 - invalid creds
                1002 - No domains
        """
        if(not token.password_correct(database)): return {"Error":True,"code":"1001","message":"Username or password is invalid."}
        data = self.db.get_data(token)
        if(data.get("domains",[]).__len__()!=0):
            return data["domains"]
        return {"Error":True,"code":"1002","message":"No domains"}
    
    def check_domain(self,domain: str, domains:dict={}, type: str = "A") -> int:
        """Checks if domain is valid, and not in use

        Args:
            domain (str): specified domain (**without** .frii.site suffix)
            domains (dict, optional): domains that user has (`get_data()["domains]`). if is None, the domain is considered invalid if there is another domain linked to it (secondary.primary.frii.site) since the server cannot verify if user owns primary.frii...
            type (str, optional): Type of the record in uppercase, supported: A,CNAME,TXT,NS. Defaults to "A".

        Returns:
            int: 1 - Success
            int: 0 - domain is not valid
            int: -1 - does not own a part of the domain (ex: mydomain.another.frii.site, where user does NOT own another.frii.site)
            int: -2 - domain is already in use
        """
        headers = {
            "X-Auth-Email": self.email, 
            "Authorization": "Bearer "+self.cf_key_r
        }
        if(not Domain.is_domain_valid(domain)): return 0
        if(type=="NS"): return 1
        if(type=="TXT"):
            if("frii.site" in domain):
                domain_parts:str = domain.split(".")
                user_domain=domain_parts[:-2]
                if(user_domain not in domains): 
                    return -1
        response:Response = requests.get(f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records?name={domain+'.frii.site'}", headers=headers) # is the domain available
        if(list(response.json().get("result",[])).__len__()!=0): return -2
        return 1

    
    def modify(self,database: 'Database', domain: str, token:'Token', new_content: str, type_:str) -> dict:
        """Modify a domain

        Args:
            database (Database): instance of `Database` class 
            domain (str): The domain wish to modify (without .frii.site suffix)
            token (Token): auth token
            new_content (str): new content of the domain
            type_ (str): type of the domain

        Returns:
            error:
                `{"Error":True, "message":.., "code":...}`
            success:
                `{"Error":False,"message":"Succesfully modified domain"}`
            codes: 
                1004: Invalid credentials
                10x1: Invalid domain (x being reason, consult `self.check_domain()`)
                1xxx: Cloudflare api issue
        """
        if(not token.password_correct(database)): return {"Error":True,"message":"Invalid credentials", "code":1004}
        data: dict = self.db.get_data(token)
        domains:dict = data["domains"]
        
        check_domain_status=self.check_domain(domain,domains,type_)
        if(check_domain_status!=1): return {"Error":True, "message":"Invalid domain", "code":int(f"10{check_domain_status*-1}1")}
        data_ = {
            "content": new_content,
            "name": domain ,
            "proxied": False,
            "type": type_, # from Dan: i added the type so you can add more records lol
            "comment": "Changed by "+(self.db.fernet.decrypt(str.encode(data['display-name']))).decode("utf-8") # a handy dandy lil message
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer "+self.cf_key_w,
            "X-Auth-Email": self.email
        }
        response = requests.patch(f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records/{data['domains'][domain]['id']}",json=data_,headers=headers)
        if(response.status_code==200):
            self.__add_domain_to_user(token=token,domain=domain,content=new_content,domain_id=None,type=type_)
            return {"Error":False,"message":"Succesfully modified domain"}
        else:
            return {"Error":True,"code":int(f"1{response.status_code}"),"message":"Backend api failed to respond with a valid status code."}
        
        
    def register(self,domain: str, content: str, token: 'Token', type: str) -> dict:
        """Registers a domain

        Args:
            domain (str): domain to register (without .frii.site suffix)
            content (str): the content of the domain
            token (Token): authorization token of user
            type (str): what type of domain it is 

        Returns:
            if error:
                `{"Error":True,"code":...,"message":...}`
            if success:
                `{"Error":False,"message":"Registered domain succesfully"}`
            codes:
                1000: Wrong creds
                1001: Invalid type
                1002: User not verified
                1003: domain limit
                10x4: Domain is not valid where `x*-1` is the reason (refer to `self.check_domain()`)
        """
        if(not token.password_correct(self.db)): return {"Error":True,"code":1000,"message":"Wrong credentials"}

        if(type.lower() not in ["a","cname","txt","ns"]): return {"Error":True,"code":1001,"message":f"Invalid type: {type}"}
        
        if(not self.db.is_verified(token)): return {"Error":True,"code":1002,"message":"Please verify your account."}
        
        amount_of_domains: int = self.get_user_domains(self.db,token).__len__()
        if(amount_of_domains > self.db.get_permission(token,"max-domains",4)): return {"Error":True,"code":1003,"message":"You have reached your domain limit"}
        
        domain_check:int=self.check_domain(domain,self.get_user_domains(self.db,token),type)
        if(domain_check!=1): return {"Error":True,"code":int(f"10{domain_check*-1}4"),"message":f"Domain is not valid. Reason No. {domain_check}"}
        
        headers = {
            "Content-Type":"application/json", 
            "Authorization": "Bearer "+self.cf_key_w, 
            "X-Auth-Email": self.email 
        }

        if(type=="CNAME" or type=="NS"): content="example.com"
        data_ = {
            "content": content,
            "name": domain, # because 'domain' is *only* the subdomain (example.frii.site->example)
            "proxied": False, # so cloudflare doesn't proxy the content
            "type": type.strip(), # the type of the record.
            "comment": "Issued by "+(self.db.fernet.decrypt(str.encode(self.db.get_data(token)["display-name"]))).decode("utf-8"), # just a handy-dandy lil feature that shows the admin (me) who registered the domain
            "ttl": 1 # auto ttl
        }
        response = requests.post(f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records",headers=headers,json=data_)
        if(response.status_code==200):
            self.__add_domain_to_user(token,domain,content,type,response.json().get("result",{}).get("id"))
        return {"Error":False,"message":"Succesfully registered"}
    