from funcs import Database as _Database
from funcs import Domain as _Domain
from funcs import Email as _Email
from funcs import Token as _Token
from  funcs.Utils import *
from funcs import Vulnerability as _Vulnerability
from flask import Response, render_template
import os
from dotenv import load_dotenv
import json
import time
Database = _Database.Database
Domain = _Domain.Domain
Email = _Email.Email
Token = _Token.Token
Vulnerability = _Vulnerability.Vulnerability

load_dotenv()

database:Database = Database(os.getenv("MONGODB_URL"),os.getenv("ENC_KEY"))
token:Token
domain:Domain = Domain(database,os.getenv("EMAIL"),os.getenv("CF_KEY_W"),os.getenv("CF_KEY_R"),os.getenv("ZONEID"))
email:Email = Email((os.getenv("RESEND_KEY")),database)
vulnerability:Vulnerability = Vulnerability(database)

def login(__token:str) -> Response:
    token = Token(__token)
    status:int = 200 if token.password_correct() else 401
    return Response(status=status)

#/sign-up
def sign_up(username:str,password:str,email:str,language:str) -> Response:
    status: int = 200 if database.create_user(username,password,email,language,time.time()) else 409
    return Response(status=status)

#/domain-is-available
def domain_is_available(__domain:str) -> Response:
    domain_status: int = domain.check_domain(__domain)
    # vercel uses python 3.9, thus why there is no switch case logic.
    responses:dict= {
        1:200,
        0:400,
        -1:401,
        -2:409
    }
    return Response(status=responses.get(domain_status))

#/register-domain
def register_domain(__domain:str,content:str,token:str,type:str) -> Response:
    domain_register_status: dict = domain.register(__domain,content,Token(token),type)
    responses:dict = {
        1000: 401,
        1001: 400,
        1002: 403,
        1003: 429,
        1004: 406,
        1014: 405,
        1024: 409
    }
    if(domain_register_status["Error"]):
        return Response(status=responses.get(domain_register_status["code"]))
    return Response(status=200)
        
#/modify-domain
def modify_domain(__domain:str, token:str, content:str, type:str) -> Response:
    status = domain.modify(database,__domain,Token(token),content)
    response:dict ={
        1001: 406,
        1011: 405,
        1021: 409,
        1004: 401
    }
    if(status["Error"]):
        return Response(status=response.get(status["code"]))
    return Response(status=200)

#/verification/<string:Code>
def verification(code:str) -> Response:
    if(email.verify_email(code)):
        return render_template("verify.html",status="Succesfully verified!",status_message="Your account has succefully been verified. Feel free to close this tab and return to your previous one.")
    else:
        return render_template("verify.html",status="Failed to verify",status_message="Failed to verify your account. Perhaps the code has expired?")

#/gpdr-get
def gpdr_get(token:str) -> Response:
    status = database.get_gpdr(Token(token))
    if(status["Error"]):
        return Response(401)
    return Response(response=json.dumps(status),status=200,mimetype="application/json")

#/get-user-info
def get_user_info(token) -> Response:
    responses = {
        1001: 401
    }
    status:dict = database.get_basic_user_data(Token(token))
    if("Error" in status): return Response(status=responses.get(status["code"]))
    return Response(response=json.dumps(status),status=200,mimetype="application/json")

#/get-domains
def get_domains(token:str) -> Response:
    responses = {
        1001: 401,
        1002: 404
    }
    status:dict = domain.get_user_domains(database,Token(token))
    if("Error" in status):
        return Response(status=responses.get(status["code"]))
    return Response(response=json.dumps(status),status=200,mimetype="application/json")

#/is-verified
def is_verified(token:str) -> Response:
    if(database.is_verified(Token(token))): return Response(status=200) # 200 if verified, 
    return 201 # if not verified
#/delete-domain
def delete_domain(token:str,domain_:str) -> Response:
    responses = {
        -1: 403,
        0: 401,
        1: 200
    }
    status:int = domain.delete_domain(Token(token),domain_)
    return Response(status=responses.get(status))

#/delete-user
def delete_user(token:str) -> Response:
    """Doesn't acutally delete the user, just sends an email with a verification code
    """
    user_data=database.get_basic_user_data()
    if(email.send_delete_email(user_data["email"],Token(token),user_data["username"])):
        return Response(status=200)
    return Response(status=401)

#/account-deletion<string:Code>
def account_deletion(code:str) -> Response:
    status:int = email.delete_user(code,domain)
    responses = {
        1001: 422,
        1002: 410
    }
    if(status["Error"]):
        return Response(status=responses.get(status["code"]))
    return Response(status=200)

#/resend-email
def resend_email(token:str) -> Response:
    if(email.resend_email(Token(token))): return Response(status=200)
    return Response(status=401)

#/vulnerability/report
def vulnerability_report(endpoint:str,email:str,expected:str,actual:str,importance:str,description:str,steps:str,impact:str,attacker:str) -> Response:
    status:str = vulnerability.create(endpoint,email,expected,actual,importance,description,steps,impact,attacker)
    return Response(response={"code":status},status=200,mimetype="application/json")

#/vulnerability/get
def vulnerability_get(id:str) -> Response:
    status:dict
    try:
        status = vulnerability.get_report(id)
    except(ValueError): 
        return Response(response=json.dumps({"Error":True,"code":1001,"message":"No report found"}), status=404, mimetype="application/json")
    return Response(response=json.dumps(status),stauts=200,mimetype="application/json")


    