from __future__ import annotations
from .Utils import *
import time
import resend

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from Token import Token
    from Database import Database
    from Domain import Domain
    
class Email:
    def __init__(self,api_key:str,db):
        resend.api_key = api_key
        self.db = db
        self.codes:dict={}
        self.del_codes:dict={}
    def send_verification(self,token:Token,target:str,display_name:str) -> bool:
        random_pin = generate_random_string(32)
        self.codes[random_pin] = {}
        self.codes[random_pin]["account"]=token.username
        self.codes[random_pin]["expire"]=time.time()+5*60
        r = resend.Emails.send({ 
            "from": 'send@frii.site', 
            "to": target, 
            "subject": "Verify your account",
            "html": 
            '<html><link rel="preconnect" href="https://fonts.googleapis.com"> <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin> <link href="https://fonts.googleapis.com/css2?family=Inter:wght@100..900&display=swap" rel="stylesheet"> <div class="holder"> <h1>Hello $username!</h1> <h2>Click <a href="https://server.frii.site/verification/$code">here</a> to verify your account</h2> <h3>Do <b>NOT</b> share this code!</h3> <p>This code will expire in 5 minutes.</p> <p>Link not working? Copy the text below into your browser address bar</p>https://server.frii.site/verification/$code</div></html><style> html { background-color: rgb(225,225,225); } .holder { background-color: rgb(255,255,255); width: 50vw; border-radius: 1em; padding: 2em; margin-left: auto; margin-right: auto; } *{font-family:"Inter",sans-serif}</style>'.replace("$username",display_name).replace("$code",random_pin)
        })
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
        return self.db.delete_account(Token(self.del_codes[code]["auth-token"]),__domain)
    
    def resend_email(self,token:Token) -> bool:
        """Resends an email to user

        Args:
            token (Token): user authorization token

        Returns:
            bool: if email was sent
        """
        data:dict=self.db.get_basic_user_data(token)
        if(data["verified"]): return False
        if("Error" in data): return False
        return self.send_verification(data["email"],token.username,data["username"])
    
        