from funcs import Database as _Database
from funcs import Domain as _Domain
from funcs import Email as _Email
from funcs import Token as _Token
from  funcs.Utils import *
from funcs import Vulnerability as _Vulnerability
from funcs import Api as _Api
from flask import Response, render_template
import os
from dotenv import load_dotenv
import json
import time
Database = _Database.Database
Domain = _Domain.Domain
Email = _Email.Email
Token = _Token.Token
Api = _Api.Api
Vulnerability = _Vulnerability.Vulnerability

load_dotenv()

database:Database = Database(os.getenv("MONGODB_URL"),os.getenv("ENC_KEY"))
token:Token
api:Api
domain:Domain = Domain(database,os.getenv("EMAIL"),os.getenv("CF_KEY_W"),os.getenv("CF_KEY_R"),os.getenv("ZONEID"))
email:Email = Email((os.getenv("RESEND_KEY")),database)
vulnerability:Vulnerability = Vulnerability(database)

def login(__token:str) -> Response:
    token = Token(__token)
    status:bool = token.password_correct(database)
    if(not status): return Response(status=401)
    verified: bool = database.is_verified(token)
    if(not verified): return Response(status=417)
    return Response(status=200)

#/sign-up
def sign_up(username:str,password:str,email_:str,language:str,country:str) -> Response:
    status:dict = database.create_user(username,password,email_,language,country,time.time(),email)
    responses = {
        1001: 409,
        1002: 400
    }
    if status.get("Error",False):
        return Response(status=responses.get(status))
    return Response(status=200)

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
def register_domain(__domain:str,content:str,token_:str,type_:str) -> Response:
    if(token_.startswith("$API")):
        domain.register()
        
    else:
        domain_register_status: dict = domain.register(__domain,content,Token(token_),type_)
        responses:dict = {
            1000: 401,
            1001: 400,
            1002: 403,
            1003: 429,
            1004: 406,
            1014: 405,
            1024: 409
        }
        if(domain_register_status.get("Error",False)):
            return Response(status=responses.get(domain_register_status["code"]),response=domain_register_status.get("message","No extra information given"))
        return Response(status=200)
        
#/modify-domain
def modify_domain(__domain:str, token:str, content:str, type_:str) -> Response:
    if(token.startswith("$API")):
        status = domain.modify_with_api(database,__domain,Api(token,database),content,type_)
        responses: dict = {
            1000: 200,
            1001: 403,
            1002: 422,
            1003: 500
        }
        return Response(status=responses.get(status["code"]),response=status.get("message","No extra information"))
    else:
        status = domain.modify(database,__domain,Token(token),content,type_)
        response:dict ={
            1001: 406,
            1011: 405,
            1021: 409,
            1004: 401
        }
        if(status.get("Error",False)):
            return Response(status=response.get(status["code"]),response=status.get("message","No extra information"))
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
    if(status.get("Error",False)):
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
    user_data=database.get_basic_user_data(Token(token))
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
    if(status.get("Error",False)):
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
    return Response(response=json.dumps(status),status=200,mimetype="application/json")

#/vulnerability/progress
def vulnerability_progress(id:str,progress:str,time:int,token:str) -> Response:
    if(not Token(token).password_correct(database)): return Response(status=401)
    status:int = vulnerability.report_progress(id,progress,time,Token(token))
    if(not status):
        return Response(status=403)
    return Response(status=200)

def vulnerability_status(id:str,status:str,mode:str,d_importance:int,token:str) -> Response:
    if(not Token(token).password_correct(database)): return Response(status=401)
    statuses = {
        1: 200,
        0: 422,
        -1: 403
    }
    status = vulnerability.report_status(id,status,mode,d_importance,Token(token))
    return Response(status==statuses.get(status))

#/create-api
def create_api(token:str,domains:list,permissions:list,comment:str) -> Response:
    if(not Token(token).password_correct(database)): return Response(status=401)
    try:
        status = Api.create(Token(token),permissions,domains,comment,database)
    except PermissionError:
        return Response(status=403)
    return Response(status=200, response=status)
