from __future__ import annotations
from .Utils import generate_random_string
from .Token import Token
import time
import resend
from hashlib import sha256
import bcrypt
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from Database import Database
    from Domain import Domain
    
class Email:
    def __init__(self,api_key:str,db):
        resend.api_key = api_key
        self.db:Database = db
        self.codes:dict={}
        self.del_codes:dict={}
        self.pass_codes:dict={}
    def send_verification(self,token:Token,target:str,display_name:str) -> bool:
        random_pin = generate_random_string(32)
        self.codes[random_pin] = {}
        self.codes[random_pin]["account"]=token.username
        self.codes[random_pin]["expire"]=time.time()+5*60
        try:
            r = resend.Emails.send({ 
                "from": 'send@frii.site', 
                "to": target, 
                "subject": "Verify your account",
                "html": 
                '<html><link rel="preconnect" href="https://fonts.googleapis.com"> <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin> <link href="https://fonts.googleapis.com/css2?family=Inter:wght@100..900&display=swap" rel="stylesheet"> <div class="holder"> <h1>Hello $username!</h1> <h2>Click <a href="https://server.frii.site/verification/$code">here</a> to verify your account</h2> <h3>Do <b>NOT</b> share this code!</h3> <p>This code will expire in 5 minutes.</p> <p>Link not working? Copy the text below into your browser address bar</p>https://server.frii.site/verification/$code</div></html><style> html { background-color: rgb(225,225,225); } .holder { background-color: rgb(255,255,255); width: 50vw; border-radius: 1em; padding: 2em; margin-left: auto; margin-right: auto; } *{font-family:"Inter",sans-serif}</style>'.replace("$username",display_name).replace("$code",random_pin)
            })
        except resend.exceptions.ResendError:
            return False
        return True
        
    def verify_email(self,code: str) -> bool:
        """Confirms if email verification succeeded

        Args:
            code (str): verification code

        Returns:
            bool: if verification succeeded
        """
        if(code not in self.codes): return False
        if not round(time.time()) < self.codes[code]["expire"]: return False
        self.db.update_data(username=self.codes[code]["account"],key="verified",value=True)
        del self.codes[code]
        return True
    
    def send_delete_email(self,email:str,token:Token,displayname:str) -> bool:
        """Send an account deletion email to user

        Args:
            email (str): decrypted email of account
            token (Token): user authentication
            displayname (str): the name that will be shown on the email

        Returns:
            bool: if the email was sent.
        """
        random_pin = generate_random_string(128)
        if(not token.password_correct(self.db)): return False
        self.del_codes[random_pin] = {}
        self.del_codes[random_pin]["auth-token"]=token.string_token
        self.del_codes[random_pin]["expire"] = time.time()+30*60
        r = resend.Emails.send({
            "from":"send@frii.site",
            "to": email,
            "subject": "Confirm your account deletion",
            "html": '<html><link rel="preconnect" href="https://fonts.googleapis.com"> <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin> <link href="https://fonts.googleapis.com/css2?family=Inter:wght@100..900&display=swap" rel="stylesheet"> <div class="holder"> <h1>Hello $username.</h1> <h2>Click <a href="https://server.frii.site/account-deletion/$code">here</a> to confirm the deletion of your account.</h2> <h3>Do <b>NOT</b> share this code!</h3> <p>This code will expire in 30 minutes.</p> <p>Link not working? Copy the text below into your browser address bar</p>https://server.frii.site/account-deletion/$code</div></html><style> html { background-color: rgb(225,225,225); } .holder { background-color: rgb(255,255,255); width: 50vw; border-radius: 1em; padding: 2em; margin-left: auto; margin-right: auto; } *{font-family:"Inter",sans-serif}</style>'.replace("$code",random_pin).replace("$username",displayname)
        })
        return True
    
    def initiate_account_deletion(self,token:Token)-> bool:
        if(not token.password_correct(self.db)): return False

        data = self.db.get_basic_user_data(token)
        self.send_delete_email(data["email"],token,data["username"])
        return True

    def delete_user(self,code:str, __domain:Domain) -> dict:
        """Delete users domains and account 

        Args:
            code (str): verification code

        Returns:
            error:
                `{"Error":True,"code":...,"message":...}`
            success:
                `{"Error":False...}`
            codes: 
                1001 - Invalid code
                1002 - expired
        """
        if (code not in self.del_codes): {"Error":True,"code":1001,"message":"Invalid code"}
        if (not round(time.time()) < self.del_codes[code]["expire"]): del self.del_codes[code]; return {"Error":True,"code":1002,"message":"Code expired"}
        return self.db.delete_account(Token.Token(self.del_codes[code]["auth-token"]),__domain)
    
    def resend_email(self,token:Token) -> bool:
        """Resends an email to user

        Args:
            token (Token): user authorization token

        Returns:
            bool: if email was sent
        """
        start = time.time()
        data:dict=self.db.get_basic_user_data(token)
        print(f"Getting data from db: {time.time()-start}")
        if(data["verified"]): return False
        if("Error" in data): return False
        return self.send_verification(data["email"],token.username,data["username"])
    
    def initiate_recovery(self,username:str) -> bool:
        """Sends a password recovery email to email

        Args:
            username (str): accounts username

        Returns:
            bool: if email was sent
        """
        hash_username = sha256(username.encode("utf-8")).hexdigest()
        start = time.time() 
        
        user_data = self.db.collection.find_one({"_id":hash_username})
        print(f"Getting data from db: {time.time()-start}")
    
        email = self.db.fernet.decrypt(str.encode(user_data["email"])).decode("utf-8")
        
        random_pin = generate_random_string(32)
        try:
            r = resend.Emails.send({
                "from":"send@frii.site",
                "to": email,
                "subject": "Password recovery",
                "html": '<html style="background-color: rgb(225,225,225);font-family:"Inter",sans-serif"> <link rel="preconnect" href="https://fonts.googleapis.com"> <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin> <link href="https://fonts.googleapis.com/css2?family=Inter:wght@100..900&display=swap" rel="stylesheet"> <div style="background-color: rgb(255,255,255); width: 50vw; border-radius: 1em; padding: 2em; margin-left: auto; margin-right: auto;font-family:"Inter",sans-serif;"> <h1>Hello dear frii.site user.</h1> <h2>Click <a href="https://server.frii.site/account-recovery/$code">here</a> to reset the password of your account.</h2> <h3>Do <b>NOT</b> share this code!</h3> <p>Link not working? Copy the text below into your browser address bar</p> https://server.frii.site/account-recovery/$code </div></html>'.replace("$code",random_pin)
            })
        except resend.exceptions.ResendError:
            print("Email error")
            return False
        self.pass_codes[random_pin] = {}
        self.pass_codes[random_pin]["expire"] = time.time()+30*60
        self.pass_codes[random_pin]["account"] = hash_username
        return False
    
    def reset_password(self,code:str,new_password:str) -> bool:
        print(f"New password: {new_password} codes: {self.pass_codes}")
        if(self.pass_codes.get(code,None) is None): return False
        new_password = str(sha256(new_password.encode("utf-8")).hexdigest())
        password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode(encoding='utf-8')
        self.db.collection.update_one({"_id":self.pass_codes[code]["account"]},{"$set":{"password":password}})
        del self.pass_codes[code]
        return True