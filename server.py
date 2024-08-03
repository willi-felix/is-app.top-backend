from flask import Flask, request, jsonify
from flask import render_template
from connector import *
import ipinfo
import os 
from flask_cors import CORS, cross_origin
import time
from flask_limit import RateLimiter
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'
limiter = RateLimiter(app)
CORS(app)
handler = ipinfo.getHandler(os.getenv('IPINFO_KEY'))

@app.route("/")
@cross_origin()
def index():
  return "OK",200

@app.route('/login', methods=['POST'])
def login_():
  return login(request.headers.get("X-Auth-Token"))

@limiter.rate_limit(limit=1,period=120*60)
@app.route('/sign-up', methods=['POST'])
def sign_up_():
  username = request.json.get('username')
  password = request.json.get('password')
  email = request.json.get('email')
  language = request.json.get('language')
  country = handler.getDetails(request.access_route[-1]).all
  return sign_up(
    username,
    password,
    email,
    language,
    country,
  )

@app.route('/domain-is-available',methods=["GET"])
@limiter.rate_limit(limit=50,period=300)
def domain_is_available_():
  domain_ = request.args.get("domain",None)
  return domain_is_available(domain_)

@app.route("/register-domain",methods=["POST"])
@limiter.rate_limit(limit=9,period=10800)
def register_domain_():
  domain_ = request.json.get("domain")
  token_ = request.headers.get("X-Auth-Token",request.headers.get("X-Api-Key"))
  ip = request.json.get("ip")
  type_ = request.json.get("type")
  return register_domain(domain_,ip,token_,type_)

@app.route("/modify-domain",methods=["PATCH"])
@limiter.rate_limit(limit=12,period=10*60)
def modify_domain_():
  domain_ = request.json.get("domain")
  token_ = request.headers.get("X-Auth-Token",request.headers.get("X-Api-Key"))
  content = request.json.get("content")
  type_ = request.json.get("type")
  return modify_domain(domain_,token_,content,type_)

@app.route("/verification/<string:Code>", methods=["GET"])
def verification_(Code):
  return verification(Code)

@app.route("/gdpr-get",methods=["GET"])
def gpdr_get_():
  token_=request.headers.get("X-Auth-Token")
  return gpdr_get(token_)

@app.route("/get-user-info",methods=["GET"])
def get_user_info_():
  token_ = request.headers.get("X-Auth-Token")
  return get_user_info(token_)

@app.route("/get-domains", methods=["GET"])
def get_domains_():
  token_ = request.headers.get("X-Auth-Token")
  return get_domains(token_)

@app.route("/is-verified", methods=["GET"])
def is_verified_():
  token_ = request.headers.get("X-Auth-Token")
  return is_verified(token_)

@app.route("/delete-domain",methods=["DELETE"])
def delete_domain_():
  token = request.headers.get("X-Auth-Token")
  domain = request.json.get("domain")
  return delete_domain(token, domain)

@app.route("/delete-user",methods=["DELETE"])
def delete_user_():
  token_ = request.headers.get("X-Auth-Token")
  return delete_user(token_)

@app.route("/account-deletion/<string:Code>")
def account_deletion_(Code):
  return account_deletion(Code)

@limiter.rate_limit(limit=1,period=10*60)
@app.route("/resend-email", methods=["GET"])
def resend_email_():
  return resend_email(request.headers.get("X-Auth-Token"))

@limiter.rate_limit(limit=3, period=120*60)
@app.route("/vulnerability/report", methods=["POST"])
def vulnerability_report_():
  rj=request.json
  return(vulnerability_report(rj.get("endpoint"),rj.get("contact-email"),rj.get("expected"),rj.get("actual"),rj.get("importance"),rj.get("description"),rj.get("steps"),rj.get("impact"),rj.get("attacker")))

@app.route("/vulnerability/get", methods=["GET"])
def vulnerability_get_():
  return vulnerability_get(request.headers.get("X-Auth-Token"))

@app.route("/vulnerability/progress",methods=["PATCH"])
def add_progress():
  return vulnerability_progress(request.json.get("id"),request.json.get("progress"),request.json.get("time"),request.headers.get("X-Auth-Token"))

@app.route("/vulnerability/status",methods=["PATCH"])
def update_status():
  return vulnerability_status(request.json.get("id"),request.json.get("status"),request.json.get("mode"),request.json.get("d-importance"),request.headers.get("X-Auth-Token"))

@app.route("/vulnerability/all",methods=["GET"])
def get_all():
  return get_reports(request.headers.get("X-Auth-Token"))

@app.route("/vulnerability/solve",methods=["PUT"])
def solve():
  return mark_as_solved(request.json.get("id"),request.headers.get("X-Auth-Token"))

@app.route("/vulnerability/delete",methods=["POST"])
def delete_vuln():
  return delete_report(request.json.get("id"),request.headers.get("X-Auth-Token"))

@app.route("/create-api",methods=["POST"])
def create_api_():
  print(request.headers)
  return create_api(request.headers.get("X-Auth-Token"),request.json.get("domains"),request.json.get("perms"),request.json.get("comment"))

@app.route("/get-api-keys",methods=["GET"])
def get_api_keys_():
  return get_api_keys(request.headers.get("X-Auth-Token"))

@app.route("/admin/get-email",methods=["GET"])
def admin_get_email_():
  return admin_get_email(request.headers.get("X-Auth-Token"),request.args.get("id"))

@app.route("/admin/get-emails",methods=["POST"])
def admin_get_emails_():
  return admin_get_emails(request.header.get("X-Auth-Token"),request.json.get("condition"))

if(__name__=="__main__"):
  app.run(port=5000,debug=True)
