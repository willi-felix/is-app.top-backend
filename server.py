from flask import Flask, request, jsonify
from flask import request
from funcs import *
import ipinfo
import os 
from flask_cors import CORS, cross_origin
import time
from flask_limit import RateLimiter
from dotenv import load_dotenv

load_dotenv()
"""
!!! WARNING !!!
There is NO backup anywhere. Please implement it
"""

app = Flask(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'
limiter = RateLimiter(app)
CORS(app)
handler = ipinfo.getHandler(os.getenv('IPINFO_KEY'))

@app.route("/")
@cross_origin()
def index():
  elements: str = "<!DOCTYPE html> <body style='display: inline;'><div style='display: grid;'>"
  for url in app.url_map.iter_rules():
    elements+=f"<a href={url}>{url}</a>"
    
  elements+="</div></body>"
  return elements,200
@app.route('/login', methods=['POST'])
def login():
  token = request.json.get('TOKEN')
  if(token==None):
    return 'Bad Request', 400
  return_status = load_user(token)
  return return_status


@app.route('/sign-up', methods=['POST'])
def sign_up():
  username = request.json.get('username')
  password = request.json.get('password')
  email = request.json.get('email')
  language = request.json.get('language')
  time_signed_up = time.time()
  country = handler.getDetails(request.access_route[-1]).all

  return_status = create_user(
    username,
    password,
    email,
    language,
    country,
    time_signed_up
  )
  if return_status != False: # If its succesfull
    return str(return_status),200
  else:
    return 'Conflict', 409

@app.route('/domain-is-available',methods=["GET"])
@limiter.rate_limit(limit=12,period=300)
def domain_is_available():
  domain = request.args.get("domain",None)
  return check_domain(domain)

@app.route("/register-domain",methods=["POST"])
@limiter.rate_limit(limit=9,period=10800)
def register_domain():
  domain = request.json.get("domain")
  token = request.json.get("TOKEN")
  ip = request.json.get("ip")
  type_ = request.json.get("type")
  return give_domain(domain=domain,ip=ip,token=token,type=type_)

@app.route("/modify-domain",methods=["POST"])
@limiter.rate_limit(limit=12,period=10*60)
def change_domain():
  domain = request.json.get("domain")
  token = request.json.get("TOKEN")
  ip = request.json.get("ip")
  type_ = request.json.get("type")
  return modify_domain(domain,token,ip,type_)

@app.route("/send-verification-code",methods=["POST"])
def send_user_verification():
  token = request.json.get("TOKEN")
  return send_verify_email(token)

@app.route("/verify-emailcode", methods=["POST"])
def verify_email_code():
  token = request.json.get("TOKEN")
  code = request.json.get("code")
  return verify_email(token=token,code=code)

@app.route("/get-domains", methods=["POST"])
def get_domain_list():
  token = request.json.get("TOKEN")
  result = get_user_domains(token)
  if(result[1]==200):
    return result[0]
  return result

@app.route("/is-verified", methods=["POST"])
def check_verified():
  token = request.json.get("TOKEN")
  return is_user_verified(token)

@app.route("/delete-domain",methods=["POST"])
def del_domain():
  token = request.json.get("TOKEN")
  domain = request.json.get("domain")
  return delete_domain(token, domain)

if(__name__=="__main__"):
  app.run(host='0.0.0.0', port=5000)
