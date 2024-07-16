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
  return login(request.json.get("TOKEN"))

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
@limiter.rate_limit(limit=12,period=300)
def domain_is_available_():
  domain = request.args.get("domain",None)
  return domain_is_available(domain)

@app.route("/register-domain",methods=["POST"])
@limiter.rate_limit(limit=9,period=10800)
def register_domain_():
  domain = request.json.get("domain")
  token = request.json.get("TOKEN")
  ip = request.json.get("ip")
  type_ = request.json.get("type")
  return register_domain(domain,ip,token,type_)

@app.route("/modify-domain",methods=["POST"])
@limiter.rate_limit(limit=12,period=10*60)
def modify_domain_():
  domain = request.json.get("domain")
  token = request.json.get("TOKEN")
  ip = request.json.get("ip")
  type_ = request.json.get("type")
  return modify_domain(domain,token,ip,type_)

@app.route("/verification/<string:Code>", methods=["GET"])
def verification_(Code):
  return verification(Code)

@app.route("/gdpr-get",methods=["POST"])
def gpdr_get_():
  token=request.json.get("TOKEN")
  return gpdr_get(token)

@app.route("/get-user-info",methods=["POST"])
def get_user_info_():
  token = request.json.get("TOKEN")
  return get_user_info(token)
@app.route("/get-domains", methods=["POST"])
def get_domains_():
  token = request.json.get("TOKEN")
  return get_domains(token)

@app.route("/is-verified", methods=["POST"])
def is_verified_():
  token = request.json.get("TOKEN")
  return is_verified(token)

@app.route("/delete-domain",methods=["POST"])
def delete_domain_():
  token = request.json.get("TOKEN")
  domain = request.json.get("domain")
  return delete_domain(token, domain)

@app.route("/delete-user",methods=["POST"])
def delete_user_():
  token = request.json.get("TOKEN")
  return delete_user(token)

@app.route("/account-deletion/<string:Code>")
def account_deletion_(Code):
  return account_deletion(Code)

@limiter.rate_limit(limit=1,period=10*60)
@app.route("/resend-email", methods=["POST"])
def resend_email_():
  return resend_email(request.json.get("TOKEN"))

@limiter.rate_limit(limit=3, period=120*60)
@app.route("/vulnerability/report", methods=["POST"])
def vulnerability_report_():
  rj=request.json
  return(vulnerability_report(rj.get("endpoint"),rj.get("contact-email"),rj.get("expected"),rj.get("actual"),rj.get("importance"),rj.get("description"),rj.get("steps"),rj.get("impact"),rj.get("attacker")))

@app.route("/vulnerability/get", methods=["POST"])
def vulnerability_get_():
  return vulnerability_get(request.json.get("id"))

@app.route("/vulnerability/progress",methods=["POST"])
def add_progress():
  report_progress(request.json.get("id"),request.json.get("progress"),request.json.get("time"),request.json.get("TOKEN"))
  return "OK",200

@app.route("/vulnerability/status",methods=["POST"])
def update_status():
  report_status(request.json.get("id"),request.json.get("status"),request.json.get("mode"),request.json.get("d-importance"),request.json.get("TOKEN"))
  return "OK",200

@app.route("/vulnerability/all",methods=["POST"])
def get_all():
  return get_reports(request.json.get("TOKEN"))

@app.route("/vulnerability/solve",methods=["POST"])
def solve():
  return mark_as_solved(request.json.get("id"),request.json.get("TOKEN"))

@app.route("/vulnerability/delete",methods=["POST"])
def delete_vuln():
  return delete_report(request.json.get("id"),request.json.get("TOKEN"))


if(__name__=="__main__"):
  app.run(port=5000,debug=True)
