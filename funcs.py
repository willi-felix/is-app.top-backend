"""
For the love of god, please switch away from json to something like MySQL. Json is so slow :(
"""
import json
from hashlib import sha256
from cryptography.fernet import Fernet
import os
import bcrypt
import string
import random
import time
import requests
from dotenv import load_dotenv
import resend
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.collection import Collection
from pymongo.cursor import Cursor
verif_codes: dict = {}

load_dotenv()
resend.api_key = os.getenv("RESEND_KEY")
cluster: MongoClient = MongoClient(os.getenv("MONGODB_URL"))
db: Database = cluster["database"]
collection: Collection = db["frii.site"]

def username_password_to_token(username:str, password:str) -> str:
  return f"{sha256(password.encode('utf-8'))}|{sha256(username.encode('utf-8'))}"

def generate_password(length: int) -> str:
  """
  Returns a random password THAT ISNT ENCRYPTED.
  """
  return ''.join(random.choice(string.printable) for i in range(length)) # just some random characters. not encrypted. I have no idea what this is used for

def password_is_correct(username: str, password: str) -> bool:
  data = get_data(username=username)
  return bcrypt.checkpw(password.encode("utf-8"), data["password"].encode("utf-8")) # correct creds

def generate_random_pin(lenght: int) -> str:
  return str(''.join(random.choice(string.digits) for i in range(lenght)))

def parse_token(token: str) -> list:
  """
  Parses a token into password and username. If the token is very 'invalid' (aka doesn't have a | character) it returns ["N","A"], if the token is empty, it retusn ["X,"X"]
  [password, username] # dumb ik
  """
  result: list = []
  try:
    result = token.split("|")
  except AttributeError:
    result = ["X","X"]
  if(result.__len__()!=2):
    result = ["N","A"] # returns 'N,A' if the token is garbled.
  return result

def user_logged_in(user):
  """
  Updates the 'last-login' to current date.
  """
  update_data(username=user,key="last-login",value=time.time())
  

def save_data(data: dict) -> bool:
  """
  Saves data to mongodb
  """
  collection.insert_one(data)
  return True # it always returns true, even if the write fails
  
def update_data(username: str, key: str, value: any) -> None:
  collection.update_one(
    {"_id": username},
    {"$set":{key:value},},
    upsert=False
  )

def get_data(username: str, only_first_one=True) -> dict:
  cursor: Cursor
  results_found: list = []
  cursor = collection.find({"_id":username})
  for result in cursor:
    results_found.append(result)
  if(results_found.__len__()!=0):
    if(only_first_one):
      return results_found[0]
    return result
  else:
    raise IndexError("No matches for username.")
  
def user_exists(token: str=None, username: str=None) -> bool:
  """_summary_

  Args:
      token (str, optional): Token of the user
      username (str, optional): Encrypted username of user. ([1] of token)

  Raises:
      ValueError: if token nor username is specified

  Returns:
      bool: if the user exists
  """
  cursor: Cursor
  results_found: list = []
  if(token == None and username == None):
    raise ValueError("Neither token or username was specified.")
  if(token != None):
    username = parse_token(token)[1]
    if username=="X":
      return False
  cursor = collection.find({"_id":username})
  for result in cursor:
    results_found.append(result)
  return results_found.__len__()!=0
  
def create_user(username: str, password: str, email: str, language: str, country: str, time_signed_up) -> bool:
  """
  Creates an user.
  """
  original_username=username
  username = str(sha256(username.encode("utf-8")).hexdigest()) # the token is just the username hashed
                                                            # seems like a bad ideea, but dont worry! we'll
                                                            # change it at some point. and ohh actually, it isnt'
                                                            # even the token, its just 'username'. Stupid naming, ik
  password: str = str(sha256(password.encode("utf-8")).hexdigest()) # password -> sha256 password 
  if user_exists(username=username): # If the username already exists, dont let the user sign up.
    return False
  else:
    data: dict = {}
    if language==None:
      language = "en-US" # If language isnt specified, set it to english
    fernet = Fernet(bytes(os.getenv('ENC_KEY'), 'utf-8')) # The hashing engine
    data["_id"] = username
    data['email'] = (fernet.encrypt(bytes(email,'utf-8')).decode(encoding='utf-8')) # the encrypted email, but it is less encrypted
    data['password'] = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(encoding='utf-8') # the encrypted password
    data["display-name"] = (fernet.encrypt(bytes(username,'utf-8')).decode(encoding='utf-8')) # their display name, I don't think this can be changed tho lol
    data['lang'] = language # their locale gotten from js!
    data['country'] = country # their country
    data["created"] = time_signed_up
    data["last-login"] = time.time() # :sunglasses:
    data["permissions"] = {} # the permissions
    data["verified"] = False # the user has not verified their email
    data["domains"] = {} # the domains they have
    save_data(data) # Saves that data
    send_verify_email(email,username,original_username)
    return True

def load_token(token):
  """
  Checks if username + passwords are correcct
  """
  username = parse_token(token)[1] # Gets the second part of token (username)
  password = parse_token(token)[0] # Gets the first part of token (password)
  if(user_exists(token=token)): # if the account exists
    return password_is_correct(username=username,password=password) # Checks if passwords match
  else:
    return False

def load_user(token: str) -> tuple: # 'load_user' is such a terrible name
  """ 
  Checks if token is valid.
  """
  # doesn't load_token do this excact same thing???
  if load_token(token=token):
    username: str = parse_token(token)[1]
    if(username=="X"):
      return "Unathorized",401
    if(is_user_verified(token)[1]!=200):
      return "Expectation Failed",417 # user is not verified
    user_logged_in(username) # make the user's "last logged in" to the current date
    return "OK",200 # what? ig the token is valid?
  return "Not Found",404 # what? ig the token is invalid?
  
def get_user_data(token: str): # kys if you abuse this! <3 I wrote the whole account system in a day, don't blame me for the horrible security
  """
  Returns the user's data.
  """
  # I don't think this is ever used anywhere, I'm leaving it just in case !
  username = parse_token(token)[1]
  password = parse_token(token)[0]
  if(username=="X"):
    return 405
  try:
    data = get_data(username=username)
  except IndexError: # user does not exist
    return 404
  if(user_exists(username=username)):
    if password_is_correct(username=username,password=password):
      fernet = Fernet(bytes(os.getenv('ENC_KEY'), 'utf-8'))
      return {
              "username": (fernet.decrypt(str.encode(data["display-name"]))).decode("utf-8"),
              "email": (fernet.decrypt(str.encode(data["email"]))).decode("utf-8"),
              "lang": data["lang"],
              "country": data["country"],
              "created": data["created"]
            }
    else:
      False
  else:
    return 404


def save_user(user: str) -> bool:
  """
  Doesnt do anything atm
  """
  raise NotImplementedError("This function does not do anything")

def is_domain_valid(domain: str) -> bool:
  allowed = list(string.ascii_letters)
  allowed.extend(list(string.digits))
  allowed.extend([".","-"])
  valid = all(c in allowed for c in domain) # this *might* work, super hacky tho
  return valid

def check_domain(domain: str, type: str = "A") -> tuple: # if the domain is actually domainable! cloudflare will cry otherwise.
  headers = {
    "X-Auth-Email": os.getenv("EMAIL"), 
    "Authorization": "Bearer "+os.getenv('CF_KEY_R') # cloudflare read token
  }
  if(is_domain_valid(domain)==False):
    return "Bad Request",400 # buddy, it aint a valid domain
  if(type=="NS"):
    return "OK",200
  response = requests.get(f"https://api.cloudflare.com/client/v4/zones/{os.getenv('ZONEID')}/dns_records?name={domain+'.frii.site'}", headers=headers) # hey cloudflare my beloved, is this available?
  if(response.json().get("result_info").get("total_count")==0): # if its ok and if the total count of records named that are 0.
    return "OK",200 # everything is fine! just register it already bruv
  return "Conflict",409 # I don't really know, just guessing lol

def add_domain_to_user(user: str, domain: str, ip: str,  type: str=None, domain_id: str = None, true_domain: bool=None) -> bool:
  try:
   data = get_data(username=user)
  except IndexError:
    return False
  if(data.get("domains",{}).get(domain,None)==None): # if the user is registering it for the first time, instead of updating it
    data["domains"][domain] = {}
  data["domains"][domain]["ip"] = ip
  data["domains"][domain]["registered"] = time.time() 
  if(type!=None):
    data["domains"][domain]["type"] = type # the record type; A, CNAME, or TXT
  if(true_domain!=None): # 'true_domain' = A record that points to an ip address, 'false_domain' is just a redirect.
    data["domains"][domain]["true-domain"] = true_domain
  if(domain_id!=None): # If the id isn't none, then override it. Ignore otherwise.
    data["domains"][domain]["id"] = domain_id
  return update_data(username=user,key="domains",value=data["domains"])
   
   
def give_domain(domain: str, ip: str, token: str, type: str) -> tuple: # returns html status code: ex: 'OK', 200
  username = parse_token(token)[1] # get the username from the token
  password = parse_token(token)[0] # again... why isn't this a function? 'get_username_and_password_from_token', ohh, were doing that already. mb
  if(username=="X"):
    return 'Precondition Failed', 412
  try:
    data = get_data(username=username) # load the 'database' (lmao)
  except IndexError:
    return 'Not Found', 404
  if(type not in ["A","CNAME","TXT","NS"]):
    return f'Invalid record type {type}', 405 # The type is invalid.
  amount_of_domains: int = data["domains"].__len__() # the amount of domains the user has.
  if(is_user_verified(token)[1]!=200):
    return 'Bad Request', 400 # user is not verified, therefore cannot register a domain.
  if(amount_of_domains <= data["permissions"].get("max_domains",3)): # if user's max domains are more than the current amount of domains
    if(check_domain(domain,type)[1]==200 or type=="TXT"): # If is a valid domain.
      if(user_exists(token=token)): # if user exists, check so we are not 'fucked'
        if password_is_correct(username=username,password=password): # correct creds
          headers = {
            "Content-Type":"application/json", # tryna not to confuse cf :(
            "Authorization": "Bearer "+os.getenv('CF_KEY_W'), # cloudflare token to write.
            "X-Auth-Email": os.getenv("EMAIL") # tbh: I have no idea if this is required.
          }
          fernet = Fernet(bytes(os.getenv('ENC_KEY'), 'utf-8')) # init fernet n shi
          data_ = {
            "content": ip,
            "name": domain, # because 'domain' is *only* the subdomain (example.frii.site->example)
            "proxied": False, # so cloudflare doesn't proxy the content
            "type": type.strip(), # the type of the record.
            "comment": "Issued by "+(fernet.decrypt(str.encode(data["display-name"]))).decode("utf-8"), # just a handy-dandy lil feature that shows the admin (me) who registered the domain
            "ttl": 1 # auto ttl
          }
          response = requests.post(f"https://api.cloudflare.com/client/v4/zones/{os.getenv('ZONEID')}/dns_records",headers=headers,json=data_)
          if(response.status_code==200):
            add_domain_to_user(true_domain=True,type=type,user=username,domain=domain,ip=ip,domain_id=(response.json().get("result").get("id")))
          return "OK", 200
        else:
          return 'Unauthorized', 401 # pal does NOT have the correct creds
      else:
        return 'User does not exist', 404 # user does not exist???? 
    else:
      return 'Not a valid domain', 409 # it aint a valid domain mate
  else: 
    return f'Domain limit exceeded', 405 # if the user is trying to make more domains than they are allowed to.

def modify_domain(domain: str, token: str, new_ip: str, type_:str) -> tuple:
  username = parse_token(token)[1]
  password = parse_token(token)[0]
  if(username=="X"):
    return 'Precondition Failed', 412
  if (user_exists(token=token)):
    data = get_data(username=username)
    if password_is_correct(username=username,password=password): # correct creds
      domains: dict = data["domains"]
      if(check_domain(domain,type_)[1]==200 or type=="TXT"):
        return "Unprocessable Entity",422
      if(domains.get(domain,False)!=False):
        fernet = Fernet(bytes(os.getenv('ENC_KEY'), 'utf-8'))
        data_ = {
          "content": new_ip,
          "name": domain ,
          "proxied": False,
          "type": type_, # from Dan: i added the type so you can add more records lol
          "comment": "Changed by "+(fernet.decrypt(str.encode(data['display-name']))).decode("utf-8") # a handy dandy lil message
        }
        headers = {
          "Content-Type": "application/json",
          "Authorization": "Bearer "+os.getenv('CF_KEY_W'),
          "X-Auth-Email": os.getenv("EMAIL")
        }
        response = requests.patch(f"https://api.cloudflare.com/client/v4/zones/{os.getenv('ZONEID')}/dns_records/{data['domains'][domain]['id']}",json=data_,headers=headers)
        if(response.status_code==200):
          add_domain_to_user(user=username,domain=domain,ip=new_ip,domain_id=None,type=type_)
          return "OK",200 # if its ok, then its ok!
        return "Interal Server Error", 500
      else:
        return f'No', 403 # if user does not own the domain
    else: 
      return 'Unauthorized', 401 # wrong creds :(
  else:
    return 'Not Found', 404 # the user does not exist !!1!1!1 what the fuck
  
def get_user_domains(token: str) -> tuple: 
  username = parse_token(token)[1]
  password = parse_token(token)[0]
  if(username=="X"):
    return 'Precondition Failed', 412
  if (user_exists(token=token)): # if user exists
    data = get_data(username=username)
    
    if password_is_correct(username=username,password=password): # correct creds
      if(data.get("domains",[]).__len__()!=0): # if they own a domain
          return data["domains"],200 # return the domains that the user owns.
      else:
        return "Not Found",404 # Ig im using dicts now,,,
    else:
      return "Unauthorized",401
  else:
    return "Precondition Failed",412 # The user *somehow* doesn't exist??

def send_verify_email(email: str,username:str, displayname:str) -> tuple:
  global verif_codes
  """
  Send a verification code to user.

  Args:
      email (str): the user's email
      username (str): the username.
  Returns:
      HTTP status code if the email got sent.
  """
  random_pin = generate_random_pin(64)
  verif_codes[random_pin] = {}
  verif_codes[random_pin]["account"]=username
  verif_codes[random_pin]["expire"]=time.time()+5*60
  r = resend.Emails.send({ # for some reason this email *always* goes to spam, so someone should warn the user lol
    "from": 'send@frii.site', # do not change this. 
    "to": email, # who the email should be sent to
    "subject": "Verify your account",
    "html": 
    '<html><link rel="preconnect" href="https://fonts.googleapis.com"> <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin> <link href="https://fonts.googleapis.com/css2?family=Inter:wght@100..900&display=swap" rel="stylesheet"> <div class="holder"> <h1>Hello $username!</h1> <h2>Click <a href="https://server.frii.site/verification/$code">here</a> to verify your account</h2> <h3>Do <b>NOT</b> share this code!</h3> <p>This code will expire in 5 minutes.</p> <p>Link not working? Copy the text below into your browser address bar</p>https://server.frii.site/verification/$code</div></html><style> html { background-color: rgb(225,225,225); } .holder { background-color: rgb(255,255,255); width: 50vw; border-radius: 1em; padding: 2em; margin-left: auto; margin-right: auto; } *{font-family:"Inter",sans-serif}</style>'.replace("$username",displayname).replace("$code",random_pin)

    # TODO make it more beautiful.
    }) 
  random_pin = None
  return 'OK',200 # the email got sent? idk what resend.Emails.send returns if it's unsuccesful, because it isnt documented (as of 2.3.2024 ddmmyyyy)

  
def verify_email(code: str) -> bool:
  if(code not in verif_codes): return False
  if not round(time.time()) < verif_codes[code]["expire"]: return False
  update_data(username=verif_codes[code]["account"],key="verified",value=True)
  del verif_codes[code]
  return True
  
def is_user_verified(token: str) -> tuple:
  username = parse_token(token)[1]
  password = parse_token(token)[0]
  if(username=="X"):
    return 'Precondition Failed', 412
  data = get_data(username=username)
  
  if password_is_correct(username=username,password=password): # correct creds
    verified: bool = data["verified"]
    if not verified:
      return 'Unauthorized',401
    return 'OK',200
  
  
def delete_domain(token: str, domain: str) -> tuple:
  username = parse_token(token)[1]
  password = parse_token(token)[0]
  if(username=="X"):
    return 'Precondition Failed', 412
  if (user_exists(token=token)): # if the user actually exists? theres a weird bug that crashes the server if user doesn't exist
    data = get_data(username=username)
    domains: dict = data["domains"] # dict of the domains that the user has
    if password_is_correct(username=username,password=password): # correct creds
      if(domain in domains): # user owns the domain
        headers: dict = {
          "Content-Type": "application/json",
          "Authorization": "Bearer "+os.getenv('CF_KEY_W'), # cloudflare write token
          "X-Auth-Email": os.getenv("EMAIL")
        }
        response = requests.delete(f"https://api.cloudflare.com/client/v4/zones/{os.getenv('ZONEID')}/dns_records/{data['domains'][domain]['id']}",headers=headers)
        if(response.status_code==200):
          del domains[domain]
          update_data(username=username,key="domains",value=domains)
          return "OK",200
        else:
          return 'Internal Server Error',500
      else:
        return 'Forbidden', 403 # if user does not own the domain
    else:
      return 'Unauthorized', 401 # wrong creds :(
  else:
    return 'Not Found', 404 # user does not exist    
    
# thats it, finally!
